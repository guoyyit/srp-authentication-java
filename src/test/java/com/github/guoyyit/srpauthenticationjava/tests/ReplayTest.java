package com.github.guoyyit.srpauthenticationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.srpauthenticationjava.client.SrpClient;
import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReplayTest {

    private static final Path DATA_DIR;

    static {
        try {
            DATA_DIR = Files.createTempDirectory("srp-replay-");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("srp.data-dir", () -> DATA_DIR.toString());
        registry.add("srp.iterations", () -> "1000");
    }

    @LocalServerPort
    int port;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void reusedClientPublicKeyIsRejected() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("replay-user", "pw".toCharArray());

        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake handshake = client.begin();
        String publicHex = Hex.encode(driver.toFixedWidth(handshake.A()));

        ProtocolDriver.Response first = driver.post("/api/srp/challenge",
                Map.of("identity", "replay-user", "clientPublic", publicHex));
        assertEquals(200, first.status(), first.body());
        JsonNode firstJson = mapper.readTree(first.body());

        byte[] salt = Hex.decode(firstJson.get("saltHex").asText());
        java.math.BigInteger serverPublic = new java.math.BigInteger(
                firstJson.get("serverPublicHex").asText(), 16);
        SrpClient.NegotiatedKeys keys = client.finish("replay-user", handshake, salt,
                serverPublic, "pw".toCharArray());
        ProtocolDriver.Response verify = driver.post("/api/srp/verify", Map.of(
                "handshakeId", firstJson.get("handshakeId").asText(),
                "clientProof", Hex.encode(keys.clientProof())));
        assertEquals(200, verify.status(), verify.body());

        ProtocolDriver.Response replay = driver.post("/api/srp/challenge",
                Map.of("identity", "replay-user", "clientPublic", publicHex));
        assertEquals(400, replay.status());
        JsonNode replayJson = mapper.readTree(replay.body());
        assertEquals("REPLAY_DETECTED", replayJson.get("code").asText());

        ProtocolDriver.Response audit = driver.get(
                "/api/admin/audit?type=REPLAY&identity=replay-user", null);
        JsonNode events = mapper.readTree(audit.body()).get("events");
        assertEquals(1, events.size());
    }
}
