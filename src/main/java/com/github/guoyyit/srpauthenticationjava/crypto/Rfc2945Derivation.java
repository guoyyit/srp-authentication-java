package com.github.guoyyit.srpauthenticationjava.crypto;

import java.nio.charset.StandardCharsets;

/**
 * Classic x = H(s | H(I | ":" | P)) derivation used by RFC 5054 test vectors.
 */
public final class Rfc2945Derivation implements XDerivation {

    private final String digest;

    public Rfc2945Derivation(String digest) {
        this.digest = digest;
    }

    @Override
    public String id() {
        return "RFC2945-" + digest;
    }

    @Override
    public byte[] deriveX(String identity, byte[] salt, char[] password) {
        byte[] inner = Digests.hash(digest, identitySeparator(identity, password));
        return Digests.hash(digest, salt, inner);
    }

    static byte[] identitySeparator(String identity, char[] password) {
        return (identity + ":" + new String(password)).getBytes(StandardCharsets.UTF_8);
    }
}
