package com.github.guoyyit.srpauthenticationjava.service;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.crypto.Digests;
import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpEngine;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;
import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;
import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;
import com.github.guoyyit.srpauthenticationjava.protocol.PendingHandshake;
import com.github.guoyyit.srpauthenticationjava.protocol.SessionInfo;
import com.github.guoyyit.srpauthenticationjava.storage.AuditStore;
import com.github.guoyyit.srpauthenticationjava.storage.ReplayCache;
import com.github.guoyyit.srpauthenticationjava.storage.SessionTokenStore;
import com.github.guoyyit.srpauthenticationjava.storage.VerifierStore;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Drives the two-leg SRP-6a handshake, proof verification, verifier rotation
 * and session issuance.
 */
@Service
public class AuthService {

    public record ChallengeResponse(String handshakeId, String saltHex, String serverPublicHex,
                                    String groupId, String digest, String derivation,
                                    int iterations) {
    }

    public record VerifyResponse(String serverProofHex, String token, long expiresAtEpochSecond) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final VerifierStore verifierStore;
    private final ReplayCache replayCache;
    private final SessionTokenStore tokenStore;
    private final AuditStore auditStore;
    private final LockoutService lockoutService;
    private final PolicyProperties properties;
    private final Clock clock;
    private final Map<String, PendingHandshake> handshakes = new ConcurrentHashMap<>();

    public AuthService(VerifierStore verifierStore, ReplayCache replayCache,
                       SessionTokenStore tokenStore, AuditStore auditStore,
                       LockoutService lockoutService, PolicyProperties properties, Clock clock) {
        this.verifierStore = verifierStore;
        this.replayCache = replayCache;
        this.tokenStore = tokenStore;
        this.auditStore = auditStore;
        this.lockoutService = lockoutService;
        this.properties = properties;
        this.clock = clock;
    }

    public ChallengeResponse start(String identity, String clientPublicHex, String sourceAddress) {
        String normalizedIdentity = normalizeIdentity(identity);
        lockoutService.assertNotLocked(normalizedIdentity, sourceAddress);

        StoredVerifier stored = verifierStore.find(normalizedIdentity);
        if (stored == null) {
            runDecoyHandshake();
            audit(AuditEvent.PROTOCOL_VIOLATION, normalizedIdentity, sourceAddress,
                    "unknown identity");
            throw new ProtocolException(ErrorCode.UNKNOWN_IDENTITY, "identity is not registered");
        }

        SrpEngine engine = new SrpEngine(parametersFor(stored.groupId(), stored.digest(),
                stored.derivation(), stored.iterations()));
        BigInteger clientPublic = parsePublic(clientPublicHex, engine);

        String canonical = canonicalPublicHex(engine, clientPublic);
        if (!replayCache.registerIfAbsent(canonical)) {
            audit(AuditEvent.REPLAY, normalizedIdentity, sourceAddress, "client ephemeral reuse");
            throw new ProtocolException(ErrorCode.REPLAY_DETECTED,
                    "ephemeral public key has already been used");
        }

        BigInteger verifier = new BigInteger(1, Hex.decode(stored.verifierHex()));
        BigInteger serverPrivate = engine.generatePrivateKey();
        BigInteger serverPublic = engine.serverPublic(serverPrivate, verifier);
        if (serverPublic.signum() == 0) {
            throw new ProtocolException(ErrorCode.INVALID_PUBLIC_KEY,
                    "server ephemeral key degenerate; retry");
        }

        Instant now = clock.instant();
        String handshakeId = newHandshakeId();
        handshakes.put(handshakeId, new PendingHandshake(handshakeId, normalizedIdentity,
                sourceAddress, stored, serverPrivate, serverPublic, clientPublic, now,
                now.plusSeconds(properties.getHandshakeTtlSeconds()), false));
        pruneHandshakes(now);

        return new ChallengeResponse(handshakeId, stored.saltHex(),
                Hex.encode(fixedWidth(engine, serverPublic)), stored.groupId(), stored.digest(),
                stored.derivation(), stored.iterations());
    }

    public VerifyResponse complete(String handshakeId, String clientProofHex, String sourceAddress) {
        PendingHandshake handshake = requirePending(handshakeId);
        if (!eq(handshake.sourceAddress(), sourceAddress)) {
            throw new ProtocolException(ErrorCode.SESSION_NOT_FOUND, "handshake not found");
        }

        StoredVerifier stored = handshake.verifier();
        SrpEngine engine = new SrpEngine(parametersFor(stored.groupId(), stored.digest(),
                stored.derivation(), stored.iterations()));
        byte[] claimed = parseProof(clientProofHex, engine);

        BigInteger verifier = new BigInteger(1, Hex.decode(stored.verifierHex()));
        BigInteger u = engine.scramblingU(handshake.clientPublic(), handshake.serverPublic());
        BigInteger secret = engine.serverSecret(handshake.serverPrivate(), handshake.clientPublic(),
                verifier, u);
        byte[] sessionKey = engine.sessionKey(secret);
        byte[] expected = engine.expectedClientProof(stored.identity(), Hex.decode(stored.saltHex()),
                handshake.clientPublic(), handshake.serverPublic(), verifier, sessionKey);

        if (!SrpEngine.constantTimeEquals(expected, claimed)) {
            handshakes.remove(handshake.handshakeId());
            lockoutService.recordFailure(stored.identity(), sourceAddress);
            audit(AuditEvent.AUTH_FAILURE, stored.identity(), sourceAddress, "client proof mismatch");
            throw new ProtocolException(ErrorCode.PROOF_MISMATCH, "proof verification failed");
        }

        byte[] serverProof = engine.serverProof(handshake.clientPublic(), claimed, sessionKey);
        handshakes.remove(handshake.handshakeId());
        lockoutService.recordSuccess(stored.identity(), sourceAddress);
        SessionInfo session = tokenStore.create(stored.identity(), sourceAddress);
        audit(AuditEvent.AUTH_SUCCESS, stored.identity(), sourceAddress,
                "verifierVersion=" + stored.version());
        return new VerifyResponse(Hex.encode(serverProof), session.token(),
                session.expiresAt().getEpochSecond());
    }

    public void rotate(String sessionToken, String saltHex, String verifierHex) {
        SessionInfo session;
        try {
            session = requireSession(sessionToken);
        } catch (ProtocolException e) {
            throw new ProtocolException(ErrorCode.UNAUTHORIZED,
                    "rotation requires an authenticated session");
        }
        StoredVerifier current = verifierStore.find(session.identity());
        if (current == null) {
            throw new ProtocolException(ErrorCode.UNKNOWN_IDENTITY, "identity is not registered");
        }
        byte[] salt = parseHex("salt", saltHex);
        byte[] verifierBytes = parseHex("verifier", verifierHex);
        BigInteger verifier = new BigInteger(1, verifierBytes);
        SrpEngine engine = new SrpEngine(parametersFor(current.groupId(), current.digest(),
                current.derivation(), current.iterations()));
        if (salt.length < 8 || verifier.signum() <= 0
                || verifier.compareTo(engine.parameters().group().prime()) >= 0) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT,
                    "invalid replacement salt or verifier");
        }
        Instant now = Instant.now(clock);
        StoredVerifier updated = new StoredVerifier(current.identity(), current.groupId(),
                current.digest(), current.derivation(), current.iterations(),
                Hex.encode(salt), Hex.encode(verifierBytes), current.version() + 1,
                current.createdAt(), now);
        verifierStore.save(updated);
        audit(AuditEvent.ROTATION, current.identity(), session.sourceAddress(),
                "version=" + updated.version());
    }

    PendingHandshake requirePending(String handshakeId) {
        if (handshakeId == null || handshakeId.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "handshakeId is required");
        }
        PendingHandshake handshake = handshakes.get(handshakeId.trim());
        if (handshake == null) {
            throw new ProtocolException(ErrorCode.SESSION_NOT_FOUND, "handshake not found");
        }
        if (!handshake.expiresAt().isAfter(clock.instant())) {
            handshakes.remove(handshake.handshakeId());
            throw new ProtocolException(ErrorCode.SESSION_EXPIRED, "handshake has expired");
        }
        return handshake;
    }

    SrpParameters parametersFor(String groupId, String digest, String derivation, int iterations) {
        if (groupId != null && !"rfc5054-2048".equals(groupId) && !"rfc5054-1024".equals(groupId)) {
            throw new ProtocolException(ErrorCode.POLICY_VIOLATION, "unsupported group: " + groupId);
        }
        String resolvedDigest = digest == null || digest.isBlank() ? properties.getDigest() : digest;
        String resolvedDerivation = derivation == null || derivation.isBlank()
                ? properties.getDerivation() : derivation;
        int resolvedIterations = iterations > 0 ? iterations
                : ("RFC2945".equalsIgnoreCase(resolvedDerivation) ? 1 : properties.getIterations());
        return SrpParameters.of(resolvedDigest, resolvedDerivation, resolvedIterations);
    }

    private SessionInfo requireSession(String token) {
        if (token == null || token.isBlank()) {
            throw new ProtocolException(ErrorCode.UNAUTHORIZED, "missing session token");
        }
        SessionInfo session = tokenStore.validate(token.trim());
        if (session == null) {
            throw new ProtocolException(ErrorCode.SESSION_EXPIRED, "session is invalid or expired");
        }
        return session;
    }

    private String normalizeIdentity(String identity) {
        if (identity == null || identity.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "identity is required");
        }
        String normalized = identity.trim();
        if (normalized.length() > 256
                || normalized.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "identity contains illegal chars");
        }
        return normalized;
    }

    private BigInteger parsePublic(String hex, SrpEngine engine) {
        byte[] bytes = parseHex("clientPublic", hex);
        BigInteger value;
        try {
            value = new BigInteger(1, bytes);
            engine.validatePublic(value);
        } catch (IllegalArgumentException e) {
            throw new ProtocolException(ErrorCode.INVALID_PUBLIC_KEY,
                    "ephemeral public key is zero or out of range");
        }
        return value;
    }

    private byte[] parseProof(String hex, SrpEngine engine) {
        byte[] proof = parseHex("clientProof", hex);
        int width = Digests.of(engine.parameters().digest()).getDigestLength();
        if (proof.length != width) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT,
                    "client proof must be " + width + " bytes");
        }
        return proof;
    }

    private byte[] parseHex(String name, String value) {
        try {
            if (value == null || value.isBlank() || (value.length() & 1) != 0) {
                throw new IllegalArgumentException();
            }
            return Hex.decode(value.trim());
        } catch (IllegalArgumentException e) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, name + " must be hex bytes");
        }
    }

    private String canonicalPublicHex(SrpEngine engine, BigInteger value) {
        return Hex.encode(fixedWidth(engine, value));
    }

    private String newHandshakeId() {
        byte[] raw = new byte[24];
        RANDOM.nextBytes(raw);
        return Hex.encode(raw);
    }

    /**
     * Perform equivalent-cost SRP work so unknown identities are not cheaper to
     * probe than registered ones.
     */
    private void runDecoyHandshake() {
        SrpEngine engine = new SrpEngine(SrpParameters.defaults());
        BigInteger randomVerifier = new BigInteger(256, RANDOM)
                .mod(engine.parameters().group().prime());
        engine.serverPublic(engine.generatePrivateKey(), randomVerifier);
    }

    private void pruneHandshakes(Instant now) {
        handshakes.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(now));
    }

    private byte[] fixedWidth(SrpEngine engine, BigInteger value) {
        int width = (engine.parameters().group().prime().bitLength() + 7) / 8;
        byte[] raw = value.toByteArray();
        if (raw.length == width) {
            return raw;
        }
        if (raw.length == width + 1 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, raw.length);
        }
        byte[] padded = new byte[width];
        System.arraycopy(raw, 0, padded, width - raw.length, raw.length);
        return padded;
    }

    private boolean eq(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    private void audit(String type, String identity, String sourceAddress, String detail) {
        auditStore.append(type, identity, sourceAddress == null ? "" : sourceAddress, detail);
    }
}
