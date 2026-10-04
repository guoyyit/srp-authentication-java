package com.github.guoyyit.srpauthenticationjava.protocol;

import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Server-side state of one in-progress handshake. It pins the verifier version
 * captured at handshake start so concurrent rotations cannot skew the result.
 */
public record PendingHandshake(
        String handshakeId,
        String identity,
        String sourceAddress,
        StoredVerifier verifier,
        BigInteger serverPrivate,
        BigInteger serverPublic,
        BigInteger clientPublic,
        Instant createdAt,
        Instant expiresAt,
        boolean proofSubmitted) {
}
