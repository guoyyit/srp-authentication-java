package com.github.guoyyit.srpauthenticationjava.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Pure SRP-6a arithmetic shared by client and server.
 */
public final class SrpEngine {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SrpParameters parameters;

    public SrpEngine(SrpParameters parameters) {
        this.parameters = parameters;
    }

    public SrpParameters parameters() {
        return parameters;
    }

    public BigInteger generatePrivateKey() {
        BigInteger prime = parameters.group().prime();
        byte[] random = new byte[Math.max(32, (prime.bitLength() + 7) / 8)];
        RANDOM.nextBytes(random);
        return new BigInteger(1, random).mod(prime);
    }

    public BigInteger clientPublic(BigInteger a) {
        return parameters.group().generator().modPow(a, parameters.group().prime());
    }

    public BigInteger multiplierK() {
        BigInteger prime = parameters.group().prime();
        byte[] hash = Digests.hash(parameters.digest(),
                fixedWidth(prime), fixedWidth(parameters.group().generator()));
        return new BigInteger(1, hash);
    }

    public BigInteger serverPublic(BigInteger b, BigInteger verifier) {
        BigInteger prime = parameters.group().prime();
        BigInteger term = multiplierK().multiply(verifier)
                .add(parameters.group().generator().modPow(b, prime));
        return term.mod(prime);
    }

    public void validatePublic(BigInteger value) {
        if (value == null || value.signum() <= 0
                || value.compareTo(parameters.group().prime()) >= 0) {
            throw new IllegalArgumentException("ephemeral public key out of range [1, N-1]");
        }
    }

    public BigInteger scramblingU(BigInteger clientPublic, BigInteger serverPublic) {
        validatePublic(clientPublic);
        validatePublic(serverPublic);
        byte[] hash = Digests.hash(parameters.digest(),
                fixedWidth(clientPublic), fixedWidth(serverPublic));
        BigInteger u = new BigInteger(1, hash);
        if (u.signum() == 0 || u.compareTo(parameters.group().prime()) >= 0) {
            throw new IllegalArgumentException("scrambling parameter invalid");
        }
        return u;
    }

    public BigInteger clientSecret(BigInteger a, BigInteger clientPublic, BigInteger serverPublic,
                                   BigInteger x, BigInteger u) {
        BigInteger prime = parameters.group().prime();
        BigInteger generator = parameters.group().generator();
        BigInteger base = serverPublic
                .subtract(multiplierK().multiply(generator.modPow(x, prime))).mod(prime);
        BigInteger exponent = a.add(u.multiply(x));
        return base.modPow(exponent, prime);
    }

    public BigInteger serverSecret(BigInteger b, BigInteger clientPublic, BigInteger verifier,
                                   BigInteger u) {
        BigInteger prime = parameters.group().prime();
        BigInteger base = clientPublic.multiply(verifier.modPow(u, prime)).mod(prime);
        return base.modPow(b, prime);
    }

    public byte[] sessionKey(BigInteger secret) {
        return Digests.hash(parameters.digest(), fixedWidth(secret));
    }

    public byte[] clientProof(String identity, byte[] salt, BigInteger clientPublic,
                              BigInteger serverPublic, byte[] sessionKey) {
        BigInteger prime = parameters.group().prime();
        byte[] nHash = Digests.hash(parameters.digest(), fixedWidth(prime));
        byte[] gHash = Digests.hash(parameters.digest(),
                fixedWidth(parameters.group().generator()));
        for (int i = 0; i < nHash.length; i++) {
            nHash[i] ^= gHash[i];
        }
        byte[] iHash = Digests.hash(parameters.digest(),
                identity.getBytes(StandardCharsets.UTF_8));
        return Digests.hash(parameters.digest(), nHash, iHash, salt,
                fixedWidth(clientPublic), fixedWidth(serverPublic), sessionKey);
    }

    public byte[] expectedClientProof(String identity, byte[] salt, BigInteger clientPublic,
                                      BigInteger serverPublic, BigInteger verifier,
                                      byte[] sessionKey) {
        return clientProof(identity, salt, clientPublic, serverPublic, sessionKey);
    }

    public byte[] serverProof(BigInteger clientPublic, byte[] clientProof, byte[] sessionKey) {
        return Digests.hash(parameters.digest(),
                fixedWidth(clientPublic), clientProof, sessionKey);
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    private byte[] fixedWidth(BigInteger value) {
        int width = (parameters.group().prime().bitLength() + 7) / 8;
        byte[] raw = value.toByteArray();
        if (raw.length == width) {
            return raw;
        }
        if (raw.length == width + 1 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, raw.length);
        }
        if (raw.length < width) {
            byte[] padded = new byte[width];
            System.arraycopy(raw, 0, padded, width - raw.length, raw.length);
            return padded;
        }
        throw new IllegalArgumentException("value does not fit group width");
    }
}
