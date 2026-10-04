package com.github.guoyyit.srpauthenticationjava.model;

import java.time.Instant;

/**
 * One auditable security event.
 */
public record AuditEvent(
        long id,
        Instant time,
        String type,
        String identity,
        String sourceAddress,
        String detail) {

    public static final String REGISTER = "REGISTER";
    public static final String AUTH_SUCCESS = "AUTH_SUCCESS";
    public static final String AUTH_FAILURE = "AUTH_FAILURE";
    public static final String PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION";
    public static final String ROTATION = "ROTATION";
    public static final String LOCKED = "LOCKED";
    public static final String UNLOCKED = "UNLOCKED";
    public static final String REPLAY = "REPLAY";
    public static final String TOKEN_REVOKED = "TOKEN_REVOKED";
}
