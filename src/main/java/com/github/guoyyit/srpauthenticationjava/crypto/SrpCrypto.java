package com.github.guoyyit.srpauthenticationjava.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Pure SRP-6a cryptographic primitives (RFC 2945 / RFC 5054 style).
 *
 * <p>All arithmetic is performed modulo N. Ephemeral values are rejected
 * when zero or otherwise outside [1, N-1]. Proof comparison is constant time.
 *
 * <p>Password stretching: by default PBKDF2-HMAC with the configured digest
 * and iteration count is applied to the classic SRP-6a inner value
 * {@code H(I | ":" | P)}, i.e. {@code x = PBKDF2(H(I:P), salt, iterations)}.
 * With {@code iterations = 1} and {@code legacyStretching = true} the exact
 * classic derivation {@code x = H(salt | H(I | ":" | P))} used by the RFC 5054
 * test vectors is produced.
 */
public class SrpCrypto {

    private final SrpGroup group;
    private final String digestAlgorithm;
    private final String hmacAlgorithm;
    private final int iterations;
    private final boolean legacyStretching;
    private final SecureRandom random = new SecureRandom();

    private static final BigInteger ZERO = BigInteger.ZERO;

    public SrpCrypto(SrpGroup group, String digestAlgorithm, int iterations) {
        this(group, digestAlgorithm, iterations, false);
    }

    /**
     * @param group             prime group
     * @param digestAlgorithm   JCA message digest name, e.g. "SHA-256" or "SHA-1"
     * @param iterations        PBKDF2 iteration count (>= 1)
     * @param legacyStretching  when true, use the classic single-hash derivation
     *                          required by the RFC 5054 test vectors
     */
    public SrpCrypto(SrpGroup group, String digestAlgorithm, int iterations, boolean legacyStretching) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be >= 1");
        }
        this.group = group;
        this.digestAlgorithm = digestAlgorithm;
        this.hmacAlgorithm = "Hmac" + digestAlgorithm.replace("-", "");
        this.iterations = iterations;
        this.legacyStretching = legacyStretching;
    }

    public SrpGroup getGroup() {
        return group;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public int getIterations() {
        return iterations;
    }

    public boolean isLegacyStretching() {
        return legacyStretching;
    }

    // ------------------------------------------------------------------
    // hashing helpers
    // ------------------------------------------------------------------

    public byte[] hash(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (Exception e) {
            throw new IllegalStateException("digest unavailable: " + digestAlgorithm, e);
        }
    }

    /**
     * Hashes a big integer using its minimal big-endian representation padded
     * to the byte length of N, as required by the SRP spec.
     */
    public byte[] hashPadded(BigInteger... values) {
        int length = (group.getN().bitLength() + 7) / 8;
        byte[][] encoded = new byte[values.length][];
        for (int i = 0; i < values.length; i++) {
            encoded[i] = pad(values[i], length);
        }
        return hash(encoded);
    }

    private byte[] pad(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] out;
        if (raw.length == length + 1 && raw[0] == 0) {
            out = new byte[length];
            System.arraycopy(raw, 1, out, 0, length);
            return out;
        }
        if (raw.length < length) {
            out = new byte[length];
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
            return out;
        }
        throw new IllegalArgumentException("value larger than modulus");
    }

    public byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(key, hmacAlgorithm));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable: " + hmacAlgorithm, e);
        }
    }

    // ------------------------------------------------------------------
    // SRP-6a quantities
    // ------------------------------------------------------------------

    /** Multiplier k = H(N | PAD(g)), derived from the group parameters. */
    public BigInteger k() {
        return new BigInteger(1, hashPadded(group.getN(), group.getG()));
    }

    /** Generates a random private ephemeral value in [1, N-1]. */
    public BigInteger generatePrivate() {
        BigInteger value;
        do {
            value = new BigInteger(group.getN().bitLength(), random);
        } while (value.signum() == 0 || value.compareTo(group.getN()) >= 0);
        return value;
    }

    public BigInteger clientPublic(BigInteger a) {
        return group.getG().modPow(a, group.getN());
    }

    public BigInteger serverPublic(BigInteger b, BigInteger v) {
        BigInteger n = group.getN();
        // B = (k*v + g^b) mod N
        return k().multiply(v).add(group.getG().modPow(b, n)).mod(n);
    }

    /**
     * Stretches the password into the private value x.
     */
    public byte[] stretchedX(String identity, byte[] salt, char[] password) {
        byte[] innerIdentity = (identity + ":").getBytes(StandardCharsets.UTF_8);
        byte[] inner = hash(concat(innerIdentity,
                new String(password).getBytes(StandardCharsets.UTF_8)));
        if (legacyStretching) {
            return hash(salt, inner);
        }
        return pbkdf2(inner, salt, iterations, hashLength());
    }

    private int hashLength() {
        try {
            return MessageDigest.getInstance(digestAlgorithm).digest().length;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int length) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    new String(password, StandardCharsets.ISO_8859_1).toCharArray(),
                    salt, iterations, length * 8);
            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2With" + hmacAlgorithm);
            byte[] derived = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return derived;
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 unavailable: " + hmacAlgorithm, e);
        }
    }

    public BigInteger verifier(byte[] x) {
        return group.getG().modPow(new BigInteger(1, x), group.getN());
    }

    /** u = H(PAD(A) | PAD(B)). */
    public BigInteger u(BigInteger a, BigInteger b) {
        return new BigInteger(1, hashPadded(a, b));
    }

    /**
     * Server premaster secret:
     * S = (A * v^u) ^ b mod N
     */
    /** Server premaster secret S = (A * v^u) ^ b mod N, padded to the size of N. */
    public byte[] serverPremaster(BigInteger clientA, BigInteger b, BigInteger u, BigInteger v) {
        BigInteger n = group.getN();
        BigInteger base = clientA.multiply(v.modPow(u, n)).mod(n);
        BigInteger s = base.modPow(b, n);
        return pad(s, nByteLength());
    }

    /**
     * Client premaster secret:
     * S = (B - k*g^x) ^ (a + u*x) mod N
     */
    /** Client premaster secret S = (B - k*g^x) ^ (a + u*x) mod N, padded to the size of N. */
    public byte[] clientPremaster(BigInteger a, BigInteger serverB, BigInteger u, byte[] x) {
        BigInteger n = group.getN();
        BigInteger xInt = new BigInteger(1, x);
        BigInteger base = serverB.subtract(k().multiply(group.getG().modPow(xInt, n))).mod(n);
        BigInteger exponent = a.add(u.multiply(xInt));
        BigInteger s = base.modPow(exponent, n);
        return pad(s, nByteLength());
    }

    /** Shared session key K = H(S). */
    public byte[] sessionKeyFromPremaster(byte[] premaster) {
        return hash(premaster);
    }

    /**
     * M1 = H( H(N) XOR H(g) | H(I) | s | A | B | K )
     * where K is the shared session key.
     */
    public byte[] m1(String identity, byte[] salt, BigInteger clientA, BigInteger serverB,
                     byte[] sessionKey) {
        byte[] hn = hashPadded(group.getN());
        byte[] hg = hashPadded(group.getG());
        byte[] xor = new byte[hn.length];
        for (int i = 0; i < hn.length; i++) {
            xor[i] = (byte) (hn[i] ^ hg[i]);
        }
        byte[] hi = hash(identity.getBytes(StandardCharsets.UTF_8));
        return hash(xor, hi, salt, pad(clientA, (nByteLength())),
                pad(serverB, nByteLength()), sessionKey);
    }

    /** M2 = H( A | M1 | K ). */
    public byte[] m2(BigInteger clientA, byte[] m1, byte[] sessionKey) {
        return hash(pad(clientA, nByteLength()), m1, sessionKey);
    }

    private int nByteLength() {
        return (group.getN().bitLength() + 7) / 8;
    }

    /** Constant-time byte array comparison. */
    public boolean constantTimeEquals(byte[] expected, byte[] actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected, actual);
    }

    /**
     * An ephemeral public value is invalid when null, negative, zero or not
     * strictly smaller than N.
     */
    public boolean isInvalidEphemeral(BigInteger value) {
        return value == null
                || value.signum() <= 0
                || value.compareTo(group.getN()) >= 0;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
