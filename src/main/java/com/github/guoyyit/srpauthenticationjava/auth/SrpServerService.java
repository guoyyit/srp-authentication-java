package com.github.guoyyit.srpauthenticationjava.auth;

import com.github.guoyyit.srpauthenticationjava.config.SrpProperties;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpCrypto;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpGroup;
import com.github.guoyyit.srpauthenticationjava.model.AuthSession;
import com.github.guoyyit.srpauthenticationjava.model.RegistrationRecord;
import com.github.guoyyit.srpauthenticationjava.session.SessionManager;
import com.github.guoyyit.srpauthenticationjava.store.RegistrationStore;
import com.github.guoyyit.srpauthenticationjava.web.ApiException;
import com.github.guoyyit.srpauthenticationjava.web.dto.ChangePasswordResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.HandshakeResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.RegisterResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.VerifyResponse;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Orchestrates SRP-6a registration, handshake, mutual verification and
 * verifier rotation.
 *
 * <p>Unknown identities and invalid verifiers are handled with a fixed decoy
 * record so handshake responses do not leak account existence. Each handshake
 * snapshots the verifier valid at its start, so concurrent rotation either
 * completes the handshake against its snapshot or rejects it deterministically.
 */
public class SrpServerService {

    private final RegistrationStore registrationStore;
    private final SrpProperties properties;
    private final LockoutService lockoutService;
    private final ReplayGuard replayGuard;
    private final AuditService auditService;
    private final SessionManager sessionManager;
    private final SecureRandom random = new SecureRandom();

    private final Map<String, AuthSession> handshakes = new ConcurrentHashMap<>();
    private final Map<String, RegistrationRecord> decoys = new ConcurrentHashMap<>();

    public SrpServerService(RegistrationStore registrationStore,
                            SrpProperties properties,
                            LockoutService lockoutService,
                            ReplayGuard replayGuard,
                            AuditService auditService,
                            SessionManager sessionManager) {
        this.registrationStore = registrationStore;
        this.properties = properties;
        this.lockoutService = lockoutService;
        this.replayGuard = replayGuard;
        this.auditService = auditService;
        this.sessionManager = sessionManager;
    }

    // ------------------------------------------------------------------
    // registration
    // ------------------------------------------------------------------

    public synchronized RegisterResponse register(String identity, byte[] salt,
                                                  BigInteger verifier,
                                                  String digestAlgorithm,
                                                  Integer iterations) {
        validateIdentity(identity);
        validateSalt(salt);
        validateVerifier(verifier);
        if (registrationStore.exists(identity)) {
            throw new ApiException("IDENTITY_EXISTS", "identity already registered", 409);
        }
        String digest = digestAlgorithm == null ? properties.getDigestAlgorithm() : digestAlgorithm;
        int iters = iterations == null ? properties.getIterations() : iterations;
        if (iters < 1) {
            throw new ApiException("INVALID_ITERATIONS", "iterations must be >= 1", 400);
        }

        RegistrationRecord record = new RegistrationRecord();
        record.identity = identity;
        record.salt = salt;
        record.verifier = verifier;
        record.digestAlgorithm = digest;
        record.iterations = iters;
        record.createdAt = System.currentTimeMillis();
        record.version = 1;
        registrationStore.put(record);

        auditService.record("REGISTER", identity, null, true, "registration stored atomically");
        RegisterResponse response = new RegisterResponse();
        response.identity = identity;
        response.version = record.version;
        return response;
    }

    // ------------------------------------------------------------------
    // handshake
    // ------------------------------------------------------------------

    public HandshakeResponse startHandshake(String identity, BigInteger clientPublicA,
                                            String sourceAddress) {
        validateIdentity(identity);
        if (clientPublicA == null) {
            throw new ApiException("INVALID_PUBLIC_KEY", "client ephemeral key A is required", 400);
        }

        if (lockoutService.isLocked(identity, sourceAddress)) {
            auditService.record("AUTH_LOCKED", identity, sourceAddress, false,
                    "authentication blocked by lockout policy");
            throw new ApiException("ACCOUNT_LOCKED",
                    "too many failed attempts, try again later", 423);
        }

        SrpCrypto crypto = cryptoFor(identity);
        if (crypto.isInvalidEphemeral(clientPublicA)) {
            auditService.record("AUTH_PROTOCOL_VIOLATION", identity, sourceAddress, false,
                    "client ephemeral key A is zero or out of range");
            throw new ApiException("INVALID_PUBLIC_KEY",
                    "client ephemeral key A is zero or out of range", 400);
        }

        replayGuard.checkAndRemember(identity, clientPublicA);

        boolean identityKnown = registrationStore.exists(identity);
        RegistrationRecord record = resolveRecord(identity);
        BigInteger b = crypto.generatePrivate();
        BigInteger serverPublicB = crypto.serverPublic(b, record.verifier);

        AuthSession session = new AuthSession();
        session.sessionId = newSessionId();
        session.identity = identity;
        session.sourceAddress = sourceAddress;
        session.identityKnown = identityKnown;
        session.b = b;
        session.serverPublicB = serverPublicB;
        session.clientPublicA = clientPublicA;
        session.verifierSnapshot = record.verifier;
        session.saltSnapshot = record.salt;
        session.digestAlgorithm = record.digestAlgorithm;
        session.iterations = record.iterations;
        session.createdAt = System.currentTimeMillis();
        session.expiresAt = session.createdAt
                + properties.getHandshakeTtlSeconds() * 1000L;
        session.authenticated = false;

        BigInteger u = crypto.u(clientPublicA, serverPublicB);
        byte[] premaster = crypto.serverPremaster(clientPublicA, b, u, record.verifier);
        session.sessionKey = crypto.sessionKeyFromPremaster(premaster);
        session.expectedM1 = crypto.m1(identity, record.salt,
                clientPublicA, serverPublicB, session.sessionKey);

        handshakes.put(session.sessionId, session);

        HandshakeResponse response = new HandshakeResponse();
        response.sessionId = session.sessionId;
        response.salt = Base64.getEncoder().encodeToString(record.salt);
        response.b = serverPublicB;
        response.digestAlgorithm = record.digestAlgorithm;
        response.iterations = record.iterations;
        return response;
    }

    public VerifyResponse finishHandshake(String sessionId, byte[] clientM1) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new ApiException("INVALID_SESSION", "sessionId is required", 400);
        }
        if (clientM1 == null || clientM1.length == 0) {
            throw new ApiException("INVALID_PROOF", "proof M1 is required", 400);
        }
        AuthSession session = handshakes.get(sessionId);
        if (session == null) {
            throw new ApiException("INVALID_SESSION", "unknown or expired handshake", 404);
        }
        synchronized (session) {
            if (session.authenticated) {
                auditService.record("AUTH_PROTOCOL_VIOLATION", session.identity,
                        session.sourceAddress, false, "proof resubmitted for completed session");
                throw new ApiException("SESSION_COMPLETED",
                        "handshake has already been completed", 409);
            }
            if (session.expiresAt <= System.currentTimeMillis()) {
                handshakes.remove(sessionId);
                auditService.record("AUTH_PROTOCOL_VIOLATION", session.identity,
                        session.sourceAddress, false, "handshake expired before proof");
                throw new ApiException("SESSION_EXPIRED", "handshake expired", 410);
            }

            // Deterministic rotation interaction: a verifier rotated after this
            // handshake snapshot was taken invalidates the in-progress session.
            // An unknown identity never has a real verifier to compare against;
            // it flows into the uniform proof failure below instead.
            RegistrationRecord current = session.identityKnown
                    ? registrationStore.get(session.identity) : null;
            if (session.identityKnown && (current == null
                    || !current.verifier.equals(session.verifierSnapshot))) {
                handshakes.remove(sessionId);
                auditService.record("AUTH_PROTOCOL_VIOLATION", session.identity,
                        session.sourceAddress, false,
                        "verifier rotated during handshake; session rejected");
                throw new ApiException("VERIFIER_ROTATED",
                        "registration changed; start a new handshake", 409);
            }

            SrpCrypto crypto = new SrpCrypto(SrpGroup.rfc5054_2048(),
                    session.digestAlgorithm, session.iterations, false);

            boolean matches = crypto.constantTimeEquals(session.expectedM1, clientM1);
            if (!matches) {
                handshakes.remove(sessionId);
                lockoutService.recordFailure(session.identity, session.sourceAddress);
                auditService.record("AUTH_FAILURE", session.identity,
                        session.sourceAddress, false, "client proof M1 mismatch");
                throw new ApiException("INVALID_PROOF", "proof verification failed", 401);
            }

            byte[] serverM2 = crypto.m2(session.clientPublicA,
                    session.expectedM1, session.sessionKey);
            session.authenticated = true;

            lockoutService.recordSuccess(session.identity, session.sourceAddress);
            String token = sessionManager.issue(session.identity);
            long expiresAt = sessionManager.get(token).expiresAt;

            handshakes.remove(sessionId);
            auditService.record("AUTH_SUCCESS", session.identity,
                    session.sourceAddress, true, "mutual authentication completed");

            VerifyResponse response = new VerifyResponse();
            response.identity = session.identity;
            response.m2 = Base64.getEncoder().encodeToString(serverM2);
            response.token = token;
            response.expiresAt = expiresAt;
            return response;
        }
    }

    // ------------------------------------------------------------------
    // verifier rotation (password change on an authenticated session)
    // ------------------------------------------------------------------

    public synchronized ChangePasswordResponse rotateVerifier(String token, byte[] salt,
                                                              BigInteger verifier,
                                                              String digestAlgorithm,
                                                              Integer iterations) {
        String identity = sessionManager.validate(token);
        if (identity == null) {
            throw new ApiException("INVALID_SESSION",
                    "a valid authenticated session is required to change password", 401);
        }
        validateSalt(salt);
        validateVerifier(verifier);
        String digest = digestAlgorithm == null ? properties.getDigestAlgorithm() : digestAlgorithm;
        int iters = iterations == null ? properties.getIterations() : iterations;
        if (iters < 1) {
            throw new ApiException("INVALID_ITERATIONS", "iterations must be >= 1", 400);
        }

        RegistrationRecord existing = registrationStore.get(identity);
        RegistrationRecord updated = new RegistrationRecord();
        updated.identity = identity;
        updated.salt = salt;
        updated.verifier = verifier;
        updated.digestAlgorithm = digest;
        updated.iterations = iters;
        updated.createdAt = System.currentTimeMillis();
        updated.version = existing == null ? 1 : existing.version + 1;
        registrationStore.put(updated);

        auditService.record("PASSWORD_CHANGE", identity, null, true,
                "verifier rotated atomically to version " + updated.version);

        ChangePasswordResponse response = new ChangePasswordResponse();
        response.identity = identity;
        response.version = updated.version;
        return response;
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /**
     * Returns the real record for a known identity, otherwise a stable per-identity
     * decoy record so unknown accounts cannot be enumerated from the handshake.
     */
    private RegistrationRecord resolveRecord(String identity) {
        RegistrationRecord record = registrationStore.get(identity);
        if (record != null) {
            return record;
        }
        return decoys.computeIfAbsent(identity, this::buildDecoy);
    }

    private RegistrationRecord buildDecoy(String identity) {
        SrpCrypto crypto = new SrpCrypto(SrpGroup.rfc5054_2048(),
                properties.getDigestAlgorithm(), properties.getIterations(), false);
        byte[] salt = crypto.hash(("decoy-salt|" + identity).getBytes(StandardCharsets.UTF_8));
        byte[] x = crypto.stretchedX(identity, salt, "decoy-password".toCharArray());
        RegistrationRecord decoy = new RegistrationRecord();
        decoy.identity = identity;
        decoy.salt = salt;
        decoy.verifier = crypto.verifier(x);
        decoy.digestAlgorithm = properties.getDigestAlgorithm();
        decoy.iterations = properties.getIterations();
        decoy.createdAt = 0;
        decoy.version = 0;
        return decoy;
    }

    private SrpCrypto cryptoFor(String identity) {
        RegistrationRecord record = registrationStore.get(identity);
        String digest = record == null ? properties.getDigestAlgorithm() : record.digestAlgorithm;
        int iters = record == null ? properties.getIterations() : record.iterations;
        return new SrpCrypto(SrpGroup.rfc5054_2048(), digest, iters, false);
    }

    private static void validateIdentity(String identity) {
        if (identity == null || identity.isBlank() || identity.length() > 256) {
            throw new ApiException("INVALID_IDENTITY",
                    "identity is required and must be at most 256 characters", 400);
        }
    }

    private static void validateSalt(byte[] salt) {
        if (salt == null || salt.length < 8 || salt.length > 256) {
            throw new ApiException("INVALID_SALT",
                    "salt must be between 8 and 256 bytes", 400);
        }
    }

    private void validateVerifier(BigInteger verifier) {
        if (verifier == null) {
            throw new ApiException("INVALID_VERIFIER", "verifier is required", 400);
        }
        SrpCrypto crypto = new SrpCrypto(SrpGroup.rfc5054_2048(),
                properties.getDigestAlgorithm(), properties.getIterations(), false);
        if (crypto.isInvalidEphemeral(verifier)) {
            throw new ApiException("INVALID_VERIFIER",
                    "verifier is zero or out of range", 400);
        }
    }

    private String newSessionId() {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }
}
