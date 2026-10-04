package com.github.guoyyit.srpauthenticationjava.crypto;

/**
 * Derives the SRP secret scalar x from identity, salt and password.
 */
public interface XDerivation {

    String id();

    byte[] deriveX(String identity, byte[] salt, char[] password);
}
