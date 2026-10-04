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
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReplayDetectionIntegrationTest {

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

    @Test
    void sameClientEphemeralIsRejectedTheSecondTime() {
        String identity = "replay-" + System.nanoTime();
        Map<String, Object> material =
                SrpTestClient.registrationMaterial(identity, "pw", "SHA-256", 64);
        rest.postForEntity(url("/api/srp/register"), material, Map.class);

        BigInteger reusedA = new SrpTestClient("SHA-256", 64).publicA;

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", identity);
        body.put("a", reusedA);
        ResponseEntity<Map> first =
                rest.postForEntity(url("/api/srp/handshake"), body, Map.class);
        assertEquals(200, first.getStatusCode().value());

        ResponseEntity<Map> second =
                rest.postForEntity(url("/api/srp/handshake"), body, Map.class);
        assertEquals(409, second.getStatusCode().value());
        assertEquals("REPLAY_DETECTED", second.getBody().get("error"));
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
