package com.github.guoyyit.srpauthenticationjava.auth;

import com.github.guoyyit.srpauthenticationjava.crypto.SrpCrypto;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * Detects reuse of client ephemeral public keys A.
 *
 * <p>For every identity the hash of each accepted A is persisted together with
 * a timestamp. A previously seen A is rejected as a replay. Old entries are
 * pruned once their handshakes can no longer be alive.
 */
public class ReplayGuard {

    static final String FILE_NAME = "replay";

    private final JsonFileStore fileStore;
    private final SrpCrypto crypto;
    private final long ttlMillis;
    private final Map<String, Long> seen = new HashMap<>();

    public ReplayGuard(JsonFileStore fileStore, SrpCrypto crypto, long ttlMillis) {
        this.fileStore = fileStore;
        this.crypto = crypto;
        this.ttlMillis = ttlMillis;
        ReplayLog persisted = fileStore.read(FILE_NAME, ReplayLog.class);
        if (persisted != null && persisted.seen != null) {
            seen.putAll(persisted.seen);
        }
    }

    /**
     * @throws com.github.guoyyit.srpauthenticationjava.web.ApiException when A was used before
     */
    public synchronized void checkAndRemember(String identity, BigInteger clientPublicA) {
        pruneExpired();
        String fingerprint = fingerprint(identity, clientPublicA);
        long now = System.currentTimeMillis();
        if (seen.containsKey(fingerprint)) {
            throw new com.github.guoyyit.srpauthenticationjava.web.ApiException(
                    "REPLAY_DETECTED",
                    "ephemeral public key has already been used", 409);
        }
        seen.put(fingerprint, now + ttlMillis);
        persist();
    }

    private void pruneExpired() {
        long now = System.currentTimeMillis();
        boolean changed = seen.values().removeIf(expiry -> expiry <= now);
        if (changed) {
            persist();
        }
    }

    private String fingerprint(String identity, BigInteger clientPublicA) {
        byte[] digest = crypto.hash(
                identity.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                clientPublicA.toByteArray());
        StringBuilder builder = new StringBuilder(identity.length() + digest.length * 2 + 1);
        builder.append(identity).append('|');
        for (byte b : digest) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private void persist() {
        ReplayLog snapshot = new ReplayLog();
        snapshot.seen = new HashMap<>(seen);
        fileStore.writeAtomically(FILE_NAME, snapshot);
    }

    public static class ReplayLog {
        public Map<String, Long> seen;
    }
}
