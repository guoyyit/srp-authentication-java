package com.github.guoyyit.srpauthenticationjava.integration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConcurrentRotationIntegrationTest {

    @TempDir
    static Path tempDir;

    @LocalServerPort
    int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("srp.data-dir", () -> tempDir.toString());
        registry.add("srp.iterations", () -> 32);
        registry.add("srp.max-failures", () -> 100);
    }

    @Test
    void manyConcurrentHandshakesProduceDeterministicOutcomesAgainstRotation()
            throws InterruptedException {
        String identity = "race-" + System.nanoTime();
        register(identity, "race-old");

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        AtomicInteger invalid = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult result = authenticateFull(identity, "race-old");
                    if (result.status == 200 && result.m2Accepted) {
                        success.incrementAndGet();
                    } else if (result.status == 409) {
                        rejected.incrementAndGet();
                    } else {
                        invalid.incrementAndGet();
                    }
                } catch (Exception e) {
                    invalid.incrementAndGet();
                }
            });
        }

        // Trigger rotation while handshakes are in flight.
        pool.submit(() -> {
            try {
                start.await();
                String token = authenticate(identity, "race-old");
                Map<String, Object> material = SrpTestClient.registrationMaterial(
                        identity, "race-new", "SHA-256", 32);
                material.put("token", token);
                rest.postForEntity(url("/api/srp/change-password"), material, Map.class);
            } catch (Exception ignored) {
                // the rotating client may itself race; its outcome is asserted elsewhere
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        assertEquals(0, invalid.get(),
                "every handshake must either succeed or be explicitly rejected");
        assertEquals(threads, success.get() + rejected.get());

        // After the race the new password is the only one that works.
        assertEquals(200, authenticateFull(identity, "race-new").status);
        assertEquals(401, authenticateFull(identity, "race-old").status);
    }

    @Test
    void inProgressHandshakeIsRejectedAfterRotationAndNewPasswordWorks() {
        String identity = "rotate-" + System.nanoTime();
        String oldPassword = "old-password";
        String newPassword = "new-password";

        register(identity, oldPassword);

        // Start an in-progress handshake against the old verifier.
        SrpTestClient pending = new SrpTestClient("SHA-256", 32);
        Map<?, ?> pendingHs = handshake(identity, pending.publicA);
        String pendingSession = (String) pendingHs.get("sessionId");
        byte[] pendingSalt = Base64.getDecoder().decode((String) pendingHs.get("salt"));
        BigInteger pendingB = new BigInteger(String.valueOf(pendingHs.get("b")));

        // Complete a separate authentication to obtain a change-password token.
        String token = authenticate(identity, oldPassword);

        // Rotate the verifier concurrently.
        Map<String, Object> newMaterial =
                SrpTestClient.registrationMaterial(identity, newPassword, "SHA-256", 32);
        newMaterial.put("token", token);
        ResponseEntity<Map> change = rest.postForEntity(
                url("/api/srp/change-password"), newMaterial, Map.class);
        assertEquals(200, change.getStatusCode().value());
        assertEquals(2, ((Number) change.getBody().get("version")).intValue());

        // The pre-rotation handshake must be deterministically rejected.
        byte[] staleM1 = pending.m1(identity, oldPassword, pendingSalt, pendingB);
        Map<String, Object> staleVerify = new LinkedHashMap<>();
        staleVerify.put("sessionId", pendingSession);
        staleVerify.put("m1", Base64.getEncoder().encodeToString(staleM1));
        ResponseEntity<Map> rejected =
                rest.postForEntity(url("/api/srp/verify"), staleVerify, Map.class);
        assertEquals(409, rejected.getStatusCode().value());
        assertEquals("VERIFIER_ROTATED", rejected.getBody().get("error"));

        // A fresh handshake completes mutual auth with the new password.
        AuthResult result = authenticateFull(identity, newPassword);
        assertTrue(result.m2Accepted);

        // The old password no longer works.
        AuthResult oldAttempt = authenticateFull(identity, oldPassword);
        assertEquals(401, oldAttempt.status);
    }

    private void register(String identity, String password) {
        Map<String, Object> material =
                SrpTestClient.registrationMaterial(identity, password, "SHA-256", 32);
        assertEquals(200, rest.postForEntity(
                url("/api/srp/register"), material, Map.class).getStatusCode().value());
    }

    private String authenticate(String identity, String password) {
        return authenticateFull(identity, password).token;
    }

    @SuppressWarnings("unchecked")
    private AuthResult authenticateFull(String identity, String password) {
        SrpTestClient testClient = new SrpTestClient("SHA-256", 32);
        Map<?, ?> hs = handshake(identity, testClient.publicA);
        byte[] salt = Base64.getDecoder().decode((String) hs.get("salt"));
        BigInteger b = new BigInteger(String.valueOf(hs.get("b")));
        byte[] m1 = testClient.m1(identity, password, salt, b);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionId", hs.get("sessionId"));
        body.put("m1", Base64.getEncoder().encodeToString(m1));
        ResponseEntity<Map> response =
                rest.postForEntity(url("/api/srp/verify"), body, Map.class);

        AuthResult result = new AuthResult();
        result.status = response.getStatusCode().value();
        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, Object> verifyBody = response.getBody();
            byte[] m2 = Base64.getDecoder().decode((String) verifyBody.get("m2"));
            result.m2Accepted = testClient.client.verifyServerProof(m2);
            result.token = (String) verifyBody.get("token");
        }
        return result;
    }

    private Map<?, ?> handshake(String identity, BigInteger a) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", identity);
        body.put("a", a);
        ResponseEntity<Map> response =
                rest.postForEntity(url("/api/srp/handshake"), body, Map.class);
        assertEquals(200, response.getStatusCode().value(),
                "handshake failed: " + response.getBody());
        return response.getBody();
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private static class AuthResult {
        int status;
        boolean m2Accepted;
        String token;
    }
}
