package com.github.guoyyit.srpauthenticationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SrpProtocolIntegrationTest {

    private static final Path DATA_DIR;

    static {
        try {
            DATA_DIR = Files.createTempDirectory("srp-it-");
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

    private ProtocolDriver driver() {
        return new ProtocolDriver(port);
    }

    @Test
    void httpRegisterChallengeVerifySucceeds() throws Exception {
        ProtocolDriver driver = driver();
        driver.register("alice", "password123".toCharArray());
        ProtocolDriver.SuccessfulLogin login = driver.login("alice", "password123".toCharArray());

        ProtocolDriver.Response protectedResponse = driver.get("/api/srp/protected",
                login.token());
        assertTrue(protectedResponse.is2xx());
        JsonNode body = mapper.readTree(protectedResponse.body());
        assertEquals("alice", body.get("identity").asText());

        ProtocolDriver.Response logout = driver.post("/api/srp/logout", Map.of(),
                login.token(), null);
        assertTrue(logout.is2xx());
        ProtocolDriver.Response afterLogout = driver.get("/api/srp/protected", login.token());
        assertEquals(401, afterLogout.status());
    }

    @Test
    void wrongProofRejectsWithoutStateSkew() throws Exception {
        ProtocolDriver driver = driver();
        driver.register("mallory", "secret".toCharArray());

        var client = new com.github.guoyyit.srpauthenticationjava.client.SrpClient(
                com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters.defaults());
        var handshake = client.begin();
        var challengeBody = Map.of(
                "identity", "mallory",
                "clientPublic",
                com.github.guoyyit.srpauthenticationjava.crypto.Hex.encode(
                        driver.toFixedWidth(handshake.A())));
        ProtocolDriver.Response challenge = driver.post("/api/srp/challenge", challengeBody);
        JsonNode challengeJson = mapper.readTree(challenge.body());

        var verifyBody = Map.of(
                "handshakeId", challengeJson.get("handshakeId").asText(),
                "clientProof", "00".repeat(32));
        ProtocolDriver.Response verify = driver.post("/api/srp/verify", verifyBody);
        assertEquals(400, verify.status());
        assertCode(verify, "PROOF_MISMATCH");

        ProtocolDriver.Response retry = driver.post("/api/srp/verify", verifyBody);
        assertCode(retry, "SESSION_NOT_FOUND");
    }

    @Test
    void unknownIdentityIndistinguishable() throws Exception {
        ProtocolDriver driver = driver();
        var client = new com.github.guoyyit.srpauthenticationjava.client.SrpClient(
                com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters.defaults());
        var handshake = client.begin();
        var body = Map.of(
                "identity", "ghost",
                "clientPublic",
                com.github.guoyyit.srpauthenticationjava.crypto.Hex.encode(
                        driver.toFixedWidth(handshake.A())));
        ProtocolDriver.Response response = driver.post("/api/srp/challenge", body);
        assertEquals(401, response.status());
        assertCode(response, "UNKNOWN_IDENTITY");
    }

    @Test
    void malformedInputsReturnDistinguishableErrors() throws Exception {
        ProtocolDriver driver = driver();

        ProtocolDriver.Response zero = driver.post("/api/srp/challenge",
                Map.of("identity", "alice", "clientPublic", "00".repeat(256)));
        assertEquals(400, zero.status());
        assertCode(zero, "INVALID_PUBLIC_KEY");

        ProtocolDriver.Response malformed = driver.post("/api/srp/challenge",
                Map.of("identity", "alice", "clientPublic", "not-hex"));
        assertEquals(400, malformed.status());
        assertCode(malformed, "INVALID_FORMAT");

        ProtocolDriver.Response missing = driver.post("/api/srp/challenge",
                Map.of("identity", "alice"));
        assertEquals(400, missing.status());
    }

    @Test
    void duplicateRegistrationIsRejected() throws Exception {
        ProtocolDriver driver = driver();
        driver.register("dupe", "pw".toCharArray());
        ProtocolDriver.Response second = registerRaw(driver, "dupe");
        assertEquals(400, second.status());
        assertCode(second, "IDENTITY_TAKEN");
    }

    @Test
    void auditEventsAreQueryable() throws Exception {
        ProtocolDriver driver = driver();
        driver.register("audrey", "pw".toCharArray());
        driver.login("audrey", "pw".toCharArray());
        ProtocolDriver.Response response = driver.get(
                "/api/admin/audit?identity=audrey&limit=10", null);
        assertTrue(response.is2xx());
        JsonNode events = mapper.readTree(response.body()).get("events");
        assertTrue(events.size() >= 2);
    }

    private ProtocolDriver.Response registerRaw(ProtocolDriver driver, String identity)
            throws Exception {
        return driver.post("/api/srp/register", Map.of(
                "identity", identity,
                "salt", "00".repeat(16),
                "verifier", "01".repeat(256)));
    }

    private void assertCode(ProtocolDriver.Response response, String code) {
        try {
            JsonNode body = mapper.readTree(response.body());
            assertEquals(code, body.get("code").asText());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
