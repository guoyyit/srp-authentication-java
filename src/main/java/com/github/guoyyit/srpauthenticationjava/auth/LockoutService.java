package com.github.guoyyit.srpauthenticationjava.auth;

import com.github.guoyyit.srpauthenticationjava.config.SrpProperties;
import com.github.guoyyit.srpauthenticationjava.model.LockState;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;

import java.util.HashMap;
import java.util.Map;

/**
 * Per-identity and per-(identity, source-address) failure counting with
 * time-based locking and automatic expiry. State survives restarts.
 *
 * <p>A request is locked when either the identity-wide counter or the
 * identity+source counter has reached the configured threshold within the
 * active lock window. A successful authentication resets both counters.
 */
public class LockoutService {

    static final String FILE_NAME = "locks";

    private final JsonFileStore fileStore;
    private final SrpProperties properties;
    private final Map<String, LockState> states = new HashMap<>();

    public LockoutService(JsonFileStore fileStore, SrpProperties properties) {
        this.fileStore = fileStore;
        this.properties = properties;
        Locks persisted = fileStore.read(FILE_NAME, Locks.class);
        if (persisted != null && persisted.states != null) {
            states.putAll(persisted.states);
        }
    }

    public synchronized boolean isLocked(String identity, String sourceAddress) {
        long now = System.currentTimeMillis();
        return isKeyLocked(identityKey(identity), now)
                || isKeyLocked(sourceKey(identity, sourceAddress), now);
    }

    private boolean isKeyLocked(String key, long now) {
        LockState state = states.get(key);
        if (state == null) {
            return false;
        }
        if (state.lockedUntil > now) {
            return true;
        }
        if (state.lockedUntil != 0 && state.lockedUntil <= now) {
            // Lock window elapsed: clear counters so the client starts fresh.
            states.remove(key);
            persist();
        }
        return false;
    }

    public synchronized void recordFailure(String identity, String sourceAddress) {
        long now = System.currentTimeMillis();
        bump(identityKey(identity), now);
        bump(sourceKey(identity, sourceAddress), now);
    }

    private void bump(String key, long now) {
        LockState state = states.computeIfAbsent(key, k -> {
            LockState created = new LockState();
            created.key = k;
            return created;
        });
        if (state.lockedUntil != 0 && state.lockedUntil <= now) {
            state.failures = 0;
            state.lockedUntil = 0;
        }
        state.failures++;
        state.lastFailureAt = now;
        if (state.failures >= properties.getMaxFailures()) {
            state.lockedUntil = now + properties.getLockSeconds() * 1000L;
        }
        persist();
    }

    public synchronized void recordSuccess(String identity, String sourceAddress) {
        states.remove(identityKey(identity));
        states.remove(sourceKey(identity, sourceAddress));
        persist();
    }

    /**
     * Administrative unlock: clears identity-wide and all per-source states.
     */
    public synchronized void unlock(String identity) {
        states.entrySet().removeIf(entry ->
                entry.getKey().equals(identityKey(identity))
                        || entry.getKey().startsWith("src:" + identity + "|"));
        persist();
    }

    synchronized long remainingLockMillis(String identity, String sourceAddress) {
        long now = System.currentTimeMillis();
        long until = 0;
        LockState identityState = states.get(identityKey(identity));
        LockState sourceState = states.get(sourceKey(identity, sourceAddress));
        if (identityState != null) {
            until = Math.max(until, identityState.lockedUntil);
        }
        if (sourceState != null) {
            until = Math.max(until, sourceState.lockedUntil);
        }
        return Math.max(0, until - now);
    }

    private void persist() {
        Locks snapshot = new Locks();
        snapshot.states = new HashMap<>(states);
        fileStore.writeAtomically(FILE_NAME, snapshot);
    }

    private static String identityKey(String identity) {
        return "id:" + identity;
    }

    private static String sourceKey(String identity, String sourceAddress) {
        return "src:" + identity + "|" + (sourceAddress == null ? "unknown" : sourceAddress);
    }

    public static class Locks {
        public Map<String, LockState> states;
    }
}
