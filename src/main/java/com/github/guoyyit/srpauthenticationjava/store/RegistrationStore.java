package com.github.guoyyit.srpauthenticationjava.store;

import com.github.guoyyit.srpauthenticationjava.model.RegistrationRecord;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persistent, concurrent store of SRP registration records keyed by identity.
 *
 * <p>All mutations are applied under the store lock and flushed atomically,
 * so registrations and verifier rotations survive crashes without torn state.
 */
public class RegistrationStore {

    static final String FILE_NAME = "registrations";

    private final JsonFileStore fileStore;
    private final Map<String, RegistrationRecord> records = new ConcurrentHashMap<>();

    public RegistrationStore(JsonFileStore fileStore) {
        this.fileStore = fileStore;
        Registrations persisted = fileStore.read(FILE_NAME, Registrations.class);
        if (persisted != null && persisted.records != null) {
            records.putAll(persisted.records);
        }
    }

    public RegistrationRecord get(String identity) {
        return records.get(identity);
    }

    public boolean exists(String identity) {
        return records.containsKey(identity);
    }

    public synchronized void put(RegistrationRecord record) {
        records.put(record.identity, record);
        persist();
    }

    public synchronized RegistrationRecord computeIfAbsent(String identity,
            java.util.function.Function<String, RegistrationRecord> factory) {
        RegistrationRecord existing = records.get(identity);
        if (existing != null) {
            return existing;
        }
        RegistrationRecord created = factory.apply(identity);
        records.put(identity, created);
        persist();
        return created;
    }

    public synchronized long nextVersion(String identity) {
        RegistrationRecord record = records.get(identity);
        return record == null ? 1 : record.version + 1;
    }

    private void persist() {
        Registrations snapshot = new Registrations();
        snapshot.records = new java.util.HashMap<>(records);
        fileStore.writeAtomically(FILE_NAME, snapshot);
    }

    /**
     * Serialization envelope for the whole registration map.
     */
    public static class Registrations {
        public Map<String, RegistrationRecord> records;
    }
}
