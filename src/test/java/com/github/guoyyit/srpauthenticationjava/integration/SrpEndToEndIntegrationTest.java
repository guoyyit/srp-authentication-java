package com.github.guoyyit.srpauthenticationjava.integration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SrpEndToEndIntegrationTest {

    @TempDir
    static Path tempDir;

    @LocalServerPort
    int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("srp.data-dir", () -> tempDir.toString());
        registry.add("srp.iterations", () -> 64);
        registry.add("srp.max-failures", () -> 100);
    }

    @AfterEach
    void cleanup() {
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void fullMutualAuthenticationProtectedAccessAndLogout() {
        String identity = "alice-" + System.nanoTime();
        String password = "correct horse battery staple";
        register(identity, password);

        SrpTestClient testClient = new SrpTestClient("SHA-256", 64);
        Map<String, Object> handshake = handshake(identity, testClient.publicA, null);
        String sessionId = (String) handshake.get("sessionId");
        byte[] salt = decode((String) handshake.get("salt"));
        BigInteger b = new BigInteger(String.valueOf(handshake.get("b")));

        byte[] m1 = testClient.m1(identity, password, salt, b);
        Map<String, Object> verifyBody = new LinkedHashMap<>();
        verifyBody.put("sessionId", sessionId);
        verifyBody.put("m1", Base64.getEncoder().encodeToString(m1));
        ResponseEntity<Map> verifyResponse = rest.postForEntity(
                url("/api/srp/verify"), verifyBody, Map.class);
        assertEquals(200, verifyResponse.getStatusCode().value());
        Map<?, ?> verifyResult = verifyResponse.getBody();
        assertNotNull(verifyResult);

        byte[] m2 = decode((String) verifyResult.get("m2"));
        assertTrue(testClient.client.verifyServerProof(m2),
                "client must accept the server proof M2");
        String token = (String) verifyResult.get("token");
        assertNotNull(token);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<Map> ping = rest.exchange(url("/api/protected/ping"),
                HttpMethod.GET, new HttpEntity<>(headers), Map.class);
        assertEquals(200, ping.getStatusCode().value());
        assertEquals(identity, ping.getBody().get("identity"));

        Map<String, String> logoutBody = Map.of("token", token);
        ResponseEntity<Map> logout = rest.postForEntity(
                url("/api/srp/logout"), logoutBody, Map.class);
        assertEquals(200, logout.getStatusCode().value());

        ResponseEntity<Map> pingAfter = rest.exchange(url("/api/protected/ping"),
                HttpMethod.GET, new HttpEntity<>(headers), Map.class);
        assertEquals(401, pingAfter.getStatusCode().value());
    }

    @Test
    void wrongPasswordIsRejectedAndProofsMustAgree() {
        String identity = "bob-" + System.nanoTime();
        register(identity, "right-password");

        SrpTestClient testClient = new SrpTestClient("SHA-256", 64);
        Map<String, Object> handshake = handshake(identity, testClient.publicA, null);
        byte[] salt = decode((String) handshake.get("salt"));
        BigInteger b = new BigInteger(String.valueOf(handshake.get("b")));
        byte[] m1 = testClient.m1(identity, "wrong-password", salt, b);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionId", handshake.get("sessionId"));
        body.put("m1", Base64.getEncoder().encodeToString(m1));
        ResponseEntity<Map> response = rest.postForEntity(url("/api/srp/verify"), body, Map.class);
        assertEquals(401, response.getStatusCode().value());
        assertEquals("INVALID_PROOF", response.getBody().get("error"));
    }

    @Test
    void zeroClientEphemeralIsRejectedWithDistinctCode() {
        register("zero-" + System.nanoTime(), "pw");
        ResponseEntity<Map> response = handshakeRaw(
                "zero-identity", BigInteger.ZERO, null);
        assertEquals(400, response.getStatusCode().value());
        assertEquals("INVALID_PUBLIC_KEY", response.getBody().get("error"));
    }

    @Test
    void verifierZeroIsRejectedAtRegistration() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", "badverifier");
        body.put("salt", Base64.getEncoder().encodeToString(SrpTestClient.randomSalt()));
        body.put("verifier", BigInteger.ZERO);
        ResponseEntity<Map> response = rest.postForEntity(
                url("/api/srp/register"), body, Map.class);
        assertEquals(400, response.getStatusCode().value());
        assertEquals("INVALID_VERIFIER", response.getBody().get("error"));
    }

    @Test
    void malformedJsonIsRejected() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/json");
        HttpEntity<String> entity = new HttpEntity<>("{not-json", headers);
        ResponseEntity<Map> response = rest.postForEntity(
                url("/api/srp/handshake"), entity, Map.class);
        assertEquals(400, response.getStatusCode().value());
        assertEquals("MALFORMED_MESSAGE", response.getBody().get("error"));
    }

    @Test
    void unknownIdentityCannotBeEnumeratedAndStillFailsProof() {
        String identity = "ghost-" + System.nanoTime();
        SrpTestClient testClient = new SrpTestClient("SHA-256", 64);
        ResponseEntity<Map> handshake = handshakeRaw(identity, testClient.publicA, null);
        assertEquals(200, handshake.getStatusCode().value());

        Map<?, ?> body = handshake.getBody();
        byte[] salt = decode((String) body.get("salt"));
        BigInteger b = new BigInteger(String.valueOf(body.get("b")));
        byte[] m1 = testClient.m1(identity, "whatever", salt, b);
        Map<String, Object> verifyBody = new LinkedHashMap<>();
        verifyBody.put("sessionId", body.get("sessionId"));
        verifyBody.put("m1", Base64.getEncoder().encodeToString(m1));
        ResponseEntity<Map> verifyResponse = rest.postForEntity(
                url("/api/srp/verify"), verifyBody, Map.class);
        assertEquals(401, verifyResponse.getStatusCode().value());
        assertEquals("INVALID_PROOF", verifyResponse.getBody().get("error"));
    }

    @Test
    void auditEventsAreQueryable() {
        String identity = "audit-" + System.nanoTime();
        register(identity, "pw");

        ResponseEntity<Map> response = rest.getForEntity(
                url("/api/srp/audit?identity=" + identity), Map.class);
        assertEquals(200, response.getStatusCode().value());
        List<?> events = (List<?>) response.getBody().get("events");
        assertTrue(events.stream().anyMatch(event ->
                "REGISTER".equals(((Map<?, ?>) event).get("eventType"))));
    }

    private void register(String identity, String password) {
        Map<String, Object> material =
                SrpTestClient.registrationMaterial(identity, password, "SHA-256", 64);
        ResponseEntity<Map> response = rest.postForEntity(
                url("/api/srp/register"), material, Map.class);
        assertEquals(200, response.getStatusCode().value(),
                "registration should succeed: " + response.getBody());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> handshake(String identity, BigInteger a, String source) {
        ResponseEntity<Map> response = handshakeRaw(identity, a, source);
        assertEquals(200, response.getStatusCode().value(),
                "handshake should succeed: " + response.getBody());
        return response.getBody();
    }

    private ResponseEntity<Map> handshakeRaw(String identity, BigInteger a, String source) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", identity);
        body.put("a", a);
        HttpHeaders headers = new HttpHeaders();
        if (source != null) {
            headers.set("X-Forwarded-For", source);
        }
        return rest.postForEntity(url("/api/srp/handshake"),
                new HttpEntity<>(body, headers), Map.class);
    }

    private static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }
}
