package com.github.guoyyit.srpauthenticationjava.crypto;

import java.security.MessageDigest;

/**
 * Thin accessors for JCA message digests.
 */
public final class Digests {

    private Digests() {
    }

    public static MessageDigest of(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (Exception e) {
            throw new IllegalArgumentException("unsupported digest: " + algorithm, e);
        }
    }

    public static byte[] hash(String algorithm, byte[]... parts) {
        MessageDigest digest = of(algorithm);
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }
}
