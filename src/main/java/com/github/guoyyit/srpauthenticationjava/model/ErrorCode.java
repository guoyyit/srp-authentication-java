package com.github.guoyyit.srpauthenticationjava.model;

/**
 * Distinguishable client-facing error codes. None of them reveal password
 * related information.
 */
public enum ErrorCode {
    INVALID_FORMAT,
    INVALID_PUBLIC_KEY,
    UNKNOWN_IDENTITY,
    PROOF_MISMATCH,
    REPLAY_DETECTED,
    SESSION_NOT_FOUND,
    SESSION_EXPIRED,
    ACCOUNT_LOCKED,
    UNAUTHORIZED,
    IDENTITY_TAKEN,
    POLICY_VIOLATION
}
