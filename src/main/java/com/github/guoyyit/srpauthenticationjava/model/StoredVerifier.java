package com.github.guoyyit.srpauthenticationjava.model;

import java.time.Instant;

/**
 * Persisted registration record. The password plaintext is never present; only
 * the verifier v = g^x is stored.
 */
public record StoredVerifier(
        String identity,
        String groupId,
        String digest,
        String derivation,
        int iterations,
        String saltHex,
        String verifierHex,
        long version,
        Instant createdAt,
        Instant updatedAt) {
}
