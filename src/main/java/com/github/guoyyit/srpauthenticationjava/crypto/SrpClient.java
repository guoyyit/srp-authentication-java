package com.github.guoyyit.srpauthenticationjava.crypto;

import java.math.BigInteger;

/**
 * Reference SRP-6a client used for interoperability and end-to-end tests.
 *
 * <p>Usage: {@code start()} returns A; after receiving (salt, B) the client
 * calls {@link #processChallenge} which computes M1 and the shared session key;
 * the server's M2 is then checked with {@link #verifyServerProof}.
 */
public class SrpClient {

    private final SrpCrypto crypto;
    private final SrpGroup group;

    private String identity;
    private BigInteger privateA;
    private BigInteger publicA;
    private BigInteger serverB;
    private byte[] sessionKey;
    private byte[] m1;

    public SrpClient(SrpGroup group, String digestAlgorithm, int iterations, boolean legacyStretching) {
        this.crypto = new SrpCrypto(group, digestAlgorithm, iterations, legacyStretching);
        this.group = group;
    }

    public SrpClient(String digestAlgorithm, int iterations) {
        this(SrpGroup.rfc5054_2048(), digestAlgorithm, iterations, false);
    }

    public BigInteger start() {
        this.privateA = crypto.generatePrivate();
        this.publicA = crypto.clientPublic(privateA);
        return publicA;
    }

    /**
     * Allows tests to pin the client ephemeral private value.
     */
    public void startWithPrivate(BigInteger fixedA) {
        this.privateA = fixedA;
        this.publicA = crypto.clientPublic(fixedA);
    }

    public byte[] processChallenge(String identity, char[] password, byte[] salt, BigInteger b) {
        if (crypto.isInvalidEphemeral(b)) {
            throw new IllegalArgumentException("invalid server ephemeral B");
        }
        this.identity = identity;
        this.serverB = b;
        byte[] x = crypto.stretchedX(identity, salt, password);
        BigInteger u = crypto.u(publicA, b);
        if (u.signum() == 0) {
            throw new IllegalArgumentException("u must not be zero");
        }
        byte[] s = crypto.clientPremaster(privateA, b, u, x);
        this.sessionKey = crypto.sessionKeyFromPremaster(s);
        this.m1 = crypto.m1(identity, salt, publicA, b, sessionKey);
        return m1;
    }

    public boolean verifyServerProof(byte[] serverProof) {
        if (m1 == null) {
            throw new IllegalStateException("handshake not started");
        }
        byte[] expected = crypto.m2(publicA, m1, sessionKey);
        return crypto.constantTimeEquals(expected, serverProof);
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }

    public BigInteger getPrivateA() {
        return privateA;
    }

    public BigInteger getPublicA() {
        return publicA;
    }
}
