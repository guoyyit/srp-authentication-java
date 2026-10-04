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
class LockoutTest {

    private static final Path DATA_DIR;

    static {
        try {
            DATA_DIR = Files.createTempDirectory("srp-lock-");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("srp.data-dir", () -> DATA_DIR.toString());
        registry.add("srp.iterations", () -> "1000");
        registry.add("srp.max-failures", () -> "3");
    }

    @LocalServerPort
    int port;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void repeatedFailuresLockThenUnlock() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("locked-user", "correct".toCharArray());

        for (int i = 0; i < 3; i++) {
            ProtocolDriver.Response bad = badProof(driver, "locked-user", "203.0.113.7");
            assertEquals(400, bad.status(), bad.body());
            assertEquals("PROOF_MISMATCH", mapper.readTree(bad.body()).get("code").asText());
        }

        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake handshake = client.begin();
        ProtocolDriver.Response locked = driver.post("/api/srp/challenge", Map.of(
                "identity", "locked-user",
                "clientPublic", Hex.encode(driver.toFixedWidth(handshake.A()))), null,
                "203.0.113.7");
        assertEquals(423, locked.status());
        assertEquals("ACCOUNT_LOCKED", mapper.readTree(locked.body()).get("code").asText());

        ProtocolDriver.Response unlock = driver.post("/api/admin/unlock",
                Map.of("identity", "locked-user", "sourceAddress", "203.0.113.7"));
        assertEquals(200, unlock.status(), unlock.body());

        ProtocolDriver.SuccessfulLogin login = new ProtocolDriver(port).login("locked-user",
                "correct".toCharArray());
        assertEquals(64, login.token().length());
    }

    @Test
    void lockoutIsKeyedByIdentityAndSource() throws Exception {
        ProtocolDriver driver = new ProtocolDriver(port);
        driver.register("split-user", "correct".toCharArray());

        for (int i = 0; i < 3; i++) {
            assertEquals(400, badProof(driver, "split-user", "198.51.100.1").status());
        }
        assertEquals(423, challenge(driver, "split-user", "198.51.100.1").status());

        ProtocolDriver.Response otherSource = challenge(driver, "split-user", "198.51.100.2");
        assertEquals(200, otherSource.status(), otherSource.body());

        SrpClient otherClient = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake otherHandshake = otherClient.begin();
        ProtocolDriver.Response otherUser = driver.post("/api/srp/challenge", Map.of(
                "identity", "someone-else",
                "clientPublic", Hex.encode(driver.toFixedWidth(otherHandshake.A()))), null,
                "198.51.100.1");
        assertEquals(401, otherUser.status());
    }

    private ProtocolDriver.Response badProof(ProtocolDriver driver, String identity, String source)
            throws Exception {
        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake handshake = client.begin();
        ProtocolDriver.Response challenge = driver.post("/api/srp/challenge", Map.of(
                "identity", identity,
                "clientPublic", Hex.encode(driver.toFixedWidth(handshake.A()))), null, source);
        JsonNode challengeJson = mapper.readTree(challenge.body());
        return driver.post("/api/srp/verify", Map.of(
                "handshakeId", challengeJson.get("handshakeId").asText(),
                "clientProof", "ff".repeat(32)), null, source);
    }

    private ProtocolDriver.Response challenge(ProtocolDriver driver, String identity, String source)
            throws Exception {
        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake handshake = client.begin();
        return driver.post("/api/srp/challenge", Map.of(
                "identity", identity,
                "clientPublic", Hex.encode(driver.toFixedWidth(handshake.A()))), null, source);
    }
}
