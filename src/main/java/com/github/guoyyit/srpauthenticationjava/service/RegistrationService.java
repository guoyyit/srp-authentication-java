package com.github.guoyyit.srpauthenticationjava.service;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;
import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import com.github.guoyyit.srpauthenticationjava.storage.AuditStore;
import com.github.guoyyit.srpauthenticationjava.storage.VerifierStore;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Registers identities from salt and verifier only; passwords never reach the
 * server.
 */
@Service
public class RegistrationService {

    private final VerifierStore verifierStore;
    private final AuditStore auditStore;
    private final PolicyProperties properties;

    public RegistrationService(VerifierStore verifierStore, AuditStore auditStore,
                               PolicyProperties properties) {
        this.verifierStore = verifierStore;
        this.auditStore = auditStore;
        this.properties = properties;
    }

    public StoredVerifier register(String identity, String groupId, String digest, String derivation,
                                   int iterations, String saltHex, String verifierHex) {
        String normalizedIdentity = validateIdentity(identity);
        byte[] salt = validateHex("salt", saltHex);
        byte[] verifierBytes = validateHex("verifier", verifierHex);
        String resolvedGroup = groupId == null || groupId.isBlank()
                ? "rfc5054-2048" : groupId.trim();
        String resolvedDigest = digest == null || digest.isBlank()
                ? properties.getDigest() : digest.trim();
        String resolvedDerivation = derivation == null || derivation.isBlank()
                ? properties.getDerivation() : derivation.trim();
        int resolvedIterations = iterations > 0 ? iterations
                : ("RFC2945".equalsIgnoreCase(resolvedDerivation) ? 1 : properties.getIterations());
        if (!"rfc5054-2048".equals(resolvedGroup) && !"rfc5054-1024".equals(resolvedGroup)) {
            throw new ProtocolException(ErrorCode.POLICY_VIOLATION,
                    "unsupported group: " + resolvedGroup);
        }
        BigInteger verifier = new BigInteger(1, verifierBytes);
        if (verifier.signum() <= 0) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "verifier must be positive");
        }
        if (salt.length < 8) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "salt is too short");
        }
        if (resolvedIterations < 1) {
            throw new ProtocolException(ErrorCode.POLICY_VIOLATION,
                    "iterations must be positive");
        }
        synchronized (this) {
            if (verifierStore.exists(normalizedIdentity)) {
                throw new ProtocolException(ErrorCode.IDENTITY_TAKEN, "identity already registered");
            }
            Instant now = Instant.now();
            StoredVerifier stored = new StoredVerifier(normalizedIdentity, resolvedGroup,
                    resolvedDigest,
                    resolvedDerivation, resolvedIterations, saltHex.toLowerCase(),
                    verifierHex.toLowerCase(),
                    1L, now, now);
            verifierStore.save(stored);
            auditStore.append(AuditEvent.REGISTER, normalizedIdentity, null,
                    "group=" + groupId + " derivation=" + derivation);
            return stored;
        }
    }

    public int defaultIterations() {
        return properties.getIterations();
    }

    private String validateIdentity(String identity) {
        if (identity == null || identity.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "identity is required");
        }
        String normalized = identity.trim();
        if (normalized.length() > 256 || normalized.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "identity contains illegal chars");
        }
        return normalized;
    }

    private byte[] validateHex(String name, String value) {
        try {
            if (value == null || value.isBlank() || (value.length() & 1) != 0) {
                throw new IllegalArgumentException();
            }
            return com.github.guoyyit.srpauthenticationjava.crypto.Hex.decode(value);
        } catch (IllegalArgumentException e) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, name + " must be hex bytes");
        }
    }
}
