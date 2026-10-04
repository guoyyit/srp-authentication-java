package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Replay cache with a durable backing file so restarts cannot enable replays.
 */
@Component
public class PersistentReplayCache implements ReplayCache {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path file;
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Long> expiresAtByKey = new HashMap<>();

    private final PolicyProperties properties;
    private final Clock clock;

    public PersistentReplayCache(PolicyProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        this.file = Path.of(properties.getDataDir(), "replay.json");
        try {
            Files.createDirectories(file.getParent());
            if (Files.isRegularFile(file)) {
                Map<String, Long> loaded = mapper.readValue(Files.readString(file,
                        StandardCharsets.UTF_8), new TypeReference<Map<String, Long>>() {
                });
                expiresAtByKey.putAll(loaded);
            }
            pruneExpired();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open replay cache", e);
        }
    }

    @Override
    public boolean registerIfAbsent(String publicKeyHex) {
        lock.lock();
        try {
            pruneExpired();
            long now = clock.instant().getEpochSecond();
            long expiresAt = now + properties.getReplayRetentionSeconds();
            if (expiresAtByKey.containsKey(publicKeyHex)) {
                return false;
            }
            expiresAtByKey.put(publicKeyHex, expiresAt);
            persist();
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void pruneExpired() {
        lock.lock();
        try {
            long now = clock.instant().getEpochSecond();
            boolean changed = false;
            Iterator<Map.Entry<String, Long>> iterator = expiresAtByKey.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getValue() <= now) {
                    iterator.remove();
                    changed = true;
                }
            }
            if (changed) {
                persist();
            }
        } finally {
            lock.unlock();
        }
    }

    private void persist() {
        try {
            Path temp = Files.createTempFile(file.getParent(), "replay-", ".tmp");
            Files.writeString(temp, mapper.writeValueAsString(expiresAtByKey),
                    StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist replay cache", e);
        }
    }
}
