package com.github.guoyyit.srpauthenticationjava.integration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LockoutIntegrationTest {

    @TempDir
    static Path tempDir;

    @LocalServerPort
    int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("srp.data-dir", () -> tempDir.toString());
        registry.add("srp.iterations", () -> 32);
        registry.add("srp.max-failures", () -> 3);
        registry.add("srp.lock-seconds", () -> 300);
    }

    @Test
    void locksIdentityAndSourceAfterThresholdThenAllowsUnlock() {
        String identity = "lockme-" + System.nanoTime();
        String attacker = "10.0.0.66";
        register(identity);

        for (int attempt = 0; attempt < 3; attempt++) {
            failedVerify(identity, attacker);
        }

        // Even a fresh handshake from the offending source is blocked.
        ResponseEntity<Map> blocked = handshake(identity, attacker);
        assertEquals(423, blocked.getStatusCode().value());
        assertEquals("ACCOUNT_LOCKED", blocked.getBody().get("error"));

        // Identity-wide lock also blocks other source addresses.
        ResponseEntity<Map> blockedOther = handshake(identity, "10.0.0.77");
        assertEquals(423, blockedOther.getStatusCode().value());

        // Unrelated identities are unaffected.
        String other = "other-" + System.nanoTime();
        register(other);
        assertEquals(200, handshake(other, attacker).getStatusCode().value());

        // Administrative unlock restores access.
        rest.postForEntity(url("/api/srp/admin/unlock"),
                Map.of("identity", identity), Map.class);
        assertEquals(200, handshake(identity, attacker).getStatusCode().value());
    }

    private void register(String identity) {
        Map<String, Object> material =
                SrpTestClient.registrationMaterial(identity, "secret", "SHA-256", 32);
        assertEquals(200, rest.postForEntity(
                url("/api/srp/register"), material, Map.class).getStatusCode().value());
    }

    private void failedVerify(String identity, String source) {
        SrpTestClient testClient = new SrpTestClient("SHA-256", 32);
        ResponseEntity<Map> handshake = handshakeEntity(identity, testClient.publicA, source);
        assertEquals(200, handshake.getStatusCode().value());
        Map<?, ?> hs = handshake.getBody();
        byte[] salt = Base64.getDecoder().decode((String) hs.get("salt"));
        BigInteger b = new BigInteger(String.valueOf(hs.get("b")));
        byte[] m1 = testClient.m1(identity, "wrong", salt, b);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionId", hs.get("sessionId"));
        body.put("m1", Base64.getEncoder().encodeToString(m1));
        ResponseEntity<Map> verify = rest.postForEntity(url("/api/srp/verify"), body, Map.class);
        assertEquals(401, verify.getStatusCode().value());
    }

    private ResponseEntity<Map> handshake(String identity, String source) {
        BigInteger a = new SrpTestClient("SHA-256", 32).publicA;
        return handshakeEntity(identity, a, source);
    }

    private ResponseEntity<Map> handshakeEntity(String identity, BigInteger a, String source) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", identity);
        body.put("a", a);
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", source);
        return rest.postForEntity(url("/api/srp/handshake"),
                new HttpEntity<>(body, headers), Map.class);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
