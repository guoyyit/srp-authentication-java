package com.github.guoyyit.srpauthenticationjava.model;

import java.math.BigInteger;

/**
 * Persisted per-identity registration data.
 */
public class RegistrationRecord {

    public String identity;
    public byte[] salt;
    public BigInteger verifier;
    public String digestAlgorithm;
    public int iterations;
    public long createdAt;
    public long version;

    public RegistrationRecord() {
    }
}
