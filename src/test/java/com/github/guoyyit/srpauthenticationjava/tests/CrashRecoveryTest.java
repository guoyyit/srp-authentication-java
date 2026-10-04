package com.github.guoyyit.srpauthenticationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;

import com.github.guoyyit.srpauthenticationjava.Application;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrashRecoveryTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void registrationsRotationsLocksAndAuditSurviveRestart() throws Exception {
        Path dataDir = Files.createTempDirectory("srp-crash-");

        int firstPort;
        try (ConfigurableApplicationContext first = start(dataDir, 0)) {
            firstPort = ((ServletWebServerApplicationContext) first).getWebServer().getPort();
            ProtocolDriver driver = new ProtocolDriver(firstPort);
            driver.register("persisted", "first".toCharArray());
            ProtocolDriver.SuccessfulLogin session = driver.login("persisted",
                    "first".toCharArray());

            SrpClientHelper.Registration rotated = new SrpClientHelper()
                    .registration("persisted", "rotated".toCharArray());
            ProtocolDriver.Response rotate = driver.post("/api/srp/rotate", Map.of(
                    "salt", rotated.saltHex(),
                    "verifier", rotated.verifierHex()), session.token(), null);
            assertEquals(200, rotate.status(), rotate.body());

            driver.post("/api/srp/logout", Map.of(), session.token(), null);

            SrpClientHelper attacker = new SrpClientHelper();
            for (int i = 0; i < 3; i++) {
                ProtocolDriver.Response bad = badProof(attacker, driver, "persisted",
                        "192.0.2.10");
                assertEquals(400, bad.status());
            }
            assertEquals(423, challenge(driver, "persisted", "192.0.2.10").status());
        }

        int secondPort;
        try (ConfigurableApplicationContext second = start(dataDir, 0)) {
            secondPort = ((ServletWebServerApplicationContext) second).getWebServer().getPort();
            ProtocolDriver driver = new ProtocolDriver(secondPort);

            ProtocolDriver.SuccessfulLogin login = driver.login("persisted",
                    "rotated".toCharArray());
            assertTrue(login.token().length() == 64);

            ProtocolDriver.Response stillLocked = challenge(driver, "persisted",
                    "192.0.2.10");
            assertEquals(423, stillLocked.status());
            assertEquals("ACCOUNT_LOCKED", mapper.readTree(stillLocked.body())
                    .get("code").asText());

            ProtocolDriver.Response oldPassword = null;
            oldPassword = tryOldPassword(driver);
            assertEquals(400, oldPassword.status());

            ProtocolDriver.Response audit = driver.get(
                    "/api/admin/audit?identity=persisted&limit=50", null);
            JsonNode events = mapper.readTree(audit.body()).get("events");
            assertTrue(events.size() >= 7, "audit should survive restart: " + events.size());
            boolean hasRotation = false;
            for (JsonNode event : events) {
                if ("ROTATION".equals(event.get("type").asText())) {
                    hasRotation = true;
                }
            }
            assertTrue(hasRotation);
        }
    }

    private ConfigurableApplicationContext start(Path dataDir, int port) {
        return new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.SERVLET)
                .run("--server.port=0",
                        "--srp.data-dir=" + dataDir.toString(),
                        "--srp.iterations=1000",
                        "--srp.max-failures=3");
    }

    private ProtocolDriver.Response badProof(SrpClientHelper helper, ProtocolDriver driver,
                                             String identity, String source)
            throws Exception {
        SrpClientHelper.StartedHandshake started = helper.start(driver, identity, source);
        return driver.post("/api/srp/verify", Map.of(
                "handshakeId", started.handshakeId(),
                "clientProof", "ab".repeat(32)), null, source);
    }

    private ProtocolDriver.Response challenge(ProtocolDriver driver, String identity, String source)
            throws Exception {
        SrpClientHelper helper = new SrpClientHelper();
        return helper.startRaw(driver, identity, source);
    }

    private ProtocolDriver.Response tryOldPassword(ProtocolDriver driver) throws Exception {
        SrpClientHelper helper = new SrpClientHelper();
        SrpClientHelper.StartedHandshake started = helper.startRawHandshake(driver, "persisted",
                "192.0.2.20");
        SrpClientHelper.FinishedProof proof = helper.proofWith("persisted", "first".toCharArray(),
                started);
        return driver.post("/api/srp/verify", Map.of(
                "handshakeId", started.handshakeId(),
                "clientProof", proof.proofHex()), null, "192.0.2.20");
    }
}
