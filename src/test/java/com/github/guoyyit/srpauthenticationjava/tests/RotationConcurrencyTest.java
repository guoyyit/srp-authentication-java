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

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RotationConcurrencyTest {

    private static final Path DATA_DIR;

    static {
        try {
            DATA_DIR = Files.createTempDirectory("srp-rotate-");
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
    void handshakePinsVerifierSnapshotAcrossRotation() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("rotator", "old-password".toCharArray());

        SrpClient oldClient = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake oldHandshake = oldClient.begin();
        ProtocolDriver.Response challenge = driver.post("/api/srp/challenge", Map.of(
                "identity", "rotator",
                "clientPublic", Hex.encode(driver.toFixedWidth(oldHandshake.A()))));
        assertEquals(200, challenge.status(), challenge.body());
        JsonNode challengeJson = mapper.readTree(challenge.body());

        ProtocolDriver.SuccessfulLogin admin = driver.login("rotator",
                "old-password".toCharArray());
        SrpClient newClient = new SrpClient(SrpParameters.defaults());
        SrpClient.Registration replacement = newClient.register("rotator",
                "new-password".toCharArray(), 16);
        ProtocolDriver.Response rotate = driver.post("/api/srp/rotate", Map.of(
                "salt", Hex.encode(replacement.salt()),
                "verifier", Hex.encode(driver.toFixedWidth(replacement.verifier()))),
                admin.token(), null);
        assertEquals(200, rotate.status(), rotate.body());

        byte[] salt = Hex.decode(challengeJson.get("saltHex").asText());
        BigInteger serverPublic = new BigInteger(challengeJson.get("serverPublicHex").asText(), 16);
        SrpClient.NegotiatedKeys oldKeys = oldClient.finish("rotator", oldHandshake, salt,
                serverPublic, "old-password".toCharArray());
        ProtocolDriver.Response oldVerify = driver.post("/api/srp/verify", Map.of(
                "handshakeId", challengeJson.get("handshakeId").asText(),
                "clientProof", Hex.encode(oldKeys.clientProof())));
        assertEquals(200, oldVerify.status(), oldVerify.body());

        ProtocolDriver.SuccessfulLogin newLogin = driver.login("rotator",
                "new-password".toCharArray());
        assertTrue(newLogin.token().length() > 16);

        SrpClient staleClient = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake staleHandshake = staleClient.begin();
        ProtocolDriver.Response staleChallenge = driver.post("/api/srp/challenge", Map.of(
                "identity", "rotator",
                "clientPublic", Hex.encode(driver.toFixedWidth(staleHandshake.A()))));
        JsonNode staleJson = mapper.readTree(staleChallenge.body());
        byte[] newSalt = Hex.decode(staleJson.get("saltHex").asText());
        BigInteger newServerPublic = new BigInteger(staleJson.get("serverPublicHex").asText(), 16);
        SrpClient.NegotiatedKeys staleKeys = staleClient.finish("rotator", staleHandshake,
                newSalt, newServerPublic, "old-password".toCharArray());
        ProtocolDriver.Response staleVerify = driver.post("/api/srp/verify", Map.of(
                "handshakeId", staleJson.get("handshakeId").asText(),
                "clientProof", Hex.encode(staleKeys.clientProof())));
        assertEquals(400, staleVerify.status());
        assertEquals("PROOF_MISMATCH", mapper.readTree(staleVerify.body()).get("code").asText());
    }

    @Test
    void rotationRequiresAuthenticatedSession() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("needs-auth", "pw".toCharArray());
        ProtocolDriver.Response response = driver.post("/api/srp/rotate",
                Map.of("salt", "00".repeat(16), "verifier", "01".repeat(256)));
        assertEquals(401, response.status());
        JsonNode body = mapper.readTree(response.body());
        assertEquals("UNAUTHORIZED", body.get("code").asText());
        assertFalse(body.has("verifier"));
    }

    @Test
    void concurrentRotationsLeaveExactlyOneFinalVersion() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("concurrent", "base".toCharArray());
        ProtocolDriver.SuccessfulLogin session = driver.login("concurrent",
                "base".toCharArray());

        ExecutorService pool = Executors.newFixedThreadPool(8);
        Future<?>[] futures = new Future[8];
        for (int i = 0; i < futures.length; i++) {
            final int suffix = i;
            futures[i] = pool.submit(() -> {
                try {
                    SrpClient client = new SrpClient(SrpParameters.defaults());
                    SrpClient.Registration registration = client.register("concurrent",
                            ("password-" + suffix).toCharArray(), 16);
                    driver.post("/api/srp/rotate", Map.of(
                            "salt", Hex.encode(registration.salt()),
                            "verifier", Hex.encode(driver.toFixedWidth(registration.verifier()))),
                            session.token(), null);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        for (Future<?> future : futures) {
            future.get();
        }
        pool.shutdown();

        ProtocolDriver.Response audit = driver.get(
                "/api/admin/audit?type=ROTATION&identity=concurrent&limit=20", null);
        JsonNode events = mapper.readTree(audit.body()).get("events");
        assertEquals(8, events.size());
    }
}
