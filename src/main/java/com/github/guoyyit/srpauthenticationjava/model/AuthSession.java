package com.github.guoyyit.srpauthenticationjava.model;

import java.math.BigInteger;

/**
 * Server-side state of an in-progress SRP handshake.
 */
public class AuthSession {

    public String sessionId;
    public String identity;
    public String sourceAddress;
    public boolean identityKnown;
    public BigInteger b;
    public BigInteger serverPublicB;
    public BigInteger clientPublicA;
    public BigInteger verifierSnapshot;
    public byte[] saltSnapshot;
    public String digestAlgorithm;
    public int iterations;
    public byte[] sessionKey;
    public byte[] expectedM1;
    public long createdAt;
    public long expiresAt;
    public boolean authenticated;

    public AuthSession() {
    }
}
