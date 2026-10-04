package com.github.guoyyit.srpauthenticationjava.storage;

/**
 * Tracks ephemeral public keys already used in a handshake to reject replays.
 */
public interface ReplayCache {

    boolean registerIfAbsent(String publicKeyHex);

    void pruneExpired();
}
