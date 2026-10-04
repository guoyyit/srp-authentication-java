package com.github.guoyyit.srpauthenticationjava.protocol;

import java.time.Instant;

/**
 * An authenticated session bound to a session token.
 */
public record SessionInfo(
        String token,
        String identity,
        String sourceAddress,
        Instant createdAt,
        Instant expiresAt) {
}
