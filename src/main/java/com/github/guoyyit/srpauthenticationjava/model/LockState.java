package com.github.guoyyit.srpauthenticationjava.model;

/**
 * Failure counters and lock state for an identity/source pair.
 */
public class LockState {

    public String key;
    public int failures;
    public long lockedUntil;
    public long lastFailureAt;

    public LockState() {
    }
}
