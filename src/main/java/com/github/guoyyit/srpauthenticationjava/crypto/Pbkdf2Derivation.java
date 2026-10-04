package com.github.guoyyit.srpauthenticationjava.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Salted, iterated PBKDF2-based x derivation resistant to offline dictionary
 * attacks. The server never sees the password or x, only the verifier v=g^x.
 */
public final class Pbkdf2Derivation implements XDerivation {

    private final String digest;
    private final int iterations;

    public Pbkdf2Derivation(String digest, int iterations) {
        this.digest = digest;
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    @Override
    public String id() {
        return "PBKDF2-HMAC-" + digest + ":" + iterations;
    }

    @Override
    public byte[] deriveX(String identity, byte[] salt, char[] password) {
        if (iterations < 1) {
            throw new IllegalArgumentException("PBKDF2 iterations must be positive");
        }
        String algorithm = "PBKDF2WithHmac" + digest.replace("-", "");
        byte[] material = (identity + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[material.length + salt.length];
        System.arraycopy(material, 0, combined, 0, material.length);
        System.arraycopy(salt, 0, combined, material.length, salt.length);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            int length = Digests.of(digest).getDigestLength() * 8;
            PBEKeySpec spec = new PBEKeySpec(password, combined, iterations, length);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalArgumentException("PBKDF2 derivation failed: " + algorithm, e);
        }
    }
}
