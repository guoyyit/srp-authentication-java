package com.github.guoyyit.srpauthenticationjava.integration;

import com.github.guoyyit.srpauthenticationjava.auth.AuditService;
import com.github.guoyyit.srpauthenticationjava.auth.LockoutService;
import com.github.guoyyit.srpauthenticationjava.config.SrpProperties;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpCrypto;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpGroup;
import com.github.guoyyit.srpauthenticationjava.model.RegistrationRecord;
import com.github.guoyyit.srpauthenticationjava.session.SessionManager;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;
import com.github.guoyyit.srpauthenticationjava.store.RegistrationStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simulates a crash by rebuilding every store from the same data directory.
 * Registrations, rotations, lock state, audit records and issued sessions must
 * survive without corruption.
 */
class CrashRecoveryIntegrationTest {

    @TempDir
    Path tempDir;

    @Test
    void allDurableStateSurvivesStoreRestart() {
        SrpProperties properties = new SrpProperties();
        properties.setMaxFailures(2);
        properties.setLockSeconds(300);

        JsonFileStore firstStore = new JsonFileStore(tempDir);
        RegistrationStore registrations = new RegistrationStore(firstStore);
        AuditService audit = new AuditService(firstStore);
        LockoutService lockout = new LockoutService(firstStore, properties);
        SessionManager sessions = new SessionManager(firstStore, 3_600_000L);

        SrpCrypto crypto = new SrpCrypto(SrpGroup.rfc5054_2048(), "SHA-256", 64);
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        BigInteger verifier = crypto.verifier(
                crypto.stretchedX("carol", salt, "pw1".toCharArray()));

        RegistrationRecord record = new RegistrationRecord();
        record.identity = "carol";
        record.salt = salt;
        record.verifier = verifier;
        record.digestAlgorithm = "SHA-256";
        record.iterations = 64;
        record.createdAt = System.currentTimeMillis();
        record.version = 1;
        registrations.put(record);

        BigInteger rotated = crypto.verifier(
                crypto.stretchedX("carol", salt, "pw2".toCharArray()));
        record.verifier = rotated;
        record.version = 2;
        registrations.put(record);

        lockout.recordFailure("carol", "192.0.2.1");
        lockout.recordFailure("carol", "192.0.2.1");
        audit.record("AUTH_FAILURE", "carol", "192.0.2.1", false, "test failure");
        String token = sessions.issue("carol");

        // "Crash": discard every in-memory object and reload from disk.
        JsonFileStore secondStore = new JsonFileStore(tempDir);
        RegistrationStore reloadedRegistrations = new RegistrationStore(secondStore);
        AuditService reloadedAudit = new AuditService(secondStore);
        LockoutService reloadedLockout = new LockoutService(secondStore, properties);
        SessionManager reloadedSessions = new SessionManager(secondStore, 3_600_000L);

        RegistrationRecord recovered = reloadedRegistrations.get("carol");
        assertNotNull(recovered);
        assertEquals(2, recovered.version);
        assertEquals(rotated, recovered.verifier);
        assertEquals("SHA-256", recovered.digestAlgorithm);
        assertEquals(64, recovered.iterations);

        assertTrue(reloadedLockout.isLocked("carol", "192.0.2.1"));
        assertTrue(reloadedLockout.isLocked("carol", "198.51.100.9"),
                "identity-wide lock applies to every source address");
        assertFalse(reloadedLockout.isLocked("dave", "192.0.2.1"),
                "unrelated identity must not be locked");

        assertEquals("carol", reloadedSessions.validate(token));

        assertFalse(reloadedAudit.query("carol", "AUTH_FAILURE", 10).isEmpty());
    }
}
