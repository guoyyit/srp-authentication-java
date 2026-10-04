package com.github.guoyyit.srpauthenticationjava.session;

import com.github.guoyyit.srpauthenticationjava.model.SessionRecord;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Issues, validates and revokes time-limited, opaque session tokens.
 *
 * <p>Tokens are 256 bits of CSPRNG entropy, base64url encoded. The token
 * table is persisted atomically so restarts do not invalidate active sessions
 * and revocations remain effective.
 */
public class SessionManager {

    static final String FILE_NAME = "sessions";

    private final JsonFileStore fileStore;
    private final long ttlMillis;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, SessionRecord> sessions = new HashMap<>();

    public SessionManager(JsonFileStore fileStore, long ttlMillis) {
        this.fileStore = fileStore;
        this.ttlMillis = ttlMillis;
        Sessions persisted = fileStore.read(FILE_NAME, Sessions.class);
        if (persisted != null && persisted.sessions != null) {
            sessions.putAll(persisted.sessions);
        }
    }

    public synchronized String issue(String identity) {
        pruneExpired();
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        SessionRecord record = new SessionRecord();
        record.token = token;
        record.identity = identity;
        record.issuedAt = System.currentTimeMillis();
        record.expiresAt = record.issuedAt + ttlMillis;
        record.revoked = false;
        sessions.put(token, record);
        persist();
        return token;
    }

    /**
     * Returns the identity bound to a valid token, or null when the token is
     * unknown, expired or revoked.
     */
    public synchronized String validate(String token) {
        if (token == null) {
            return null;
        }
        SessionRecord record = sessions.get(token);
        if (record == null) {
            return null;
        }
        long now = System.currentTimeMillis();
        if (record.revoked || record.expiresAt <= now) {
            sessions.remove(token);
            persist();
            return null;
        }
        return record.identity;
    }

    public synchronized SessionRecord get(String token) {
        return sessions.get(token);
    }

    public synchronized void revoke(String token) {
        SessionRecord record = sessions.get(token);
        if (record != null) {
            record.revoked = true;
            persist();
        }
    }

    private void pruneExpired() {
        long now = System.currentTimeMillis();
        boolean changed = sessions.values().removeIf(
                record -> record.expiresAt <= now || record.revoked);
        if (changed) {
            persist();
        }
    }

    private void persist() {
        Sessions snapshot = new Sessions();
        snapshot.sessions = new HashMap<>(sessions);
        fileStore.writeAtomically(FILE_NAME, snapshot);
    }

    public static class Sessions {
        public Map<String, SessionRecord> sessions;
    }
}
