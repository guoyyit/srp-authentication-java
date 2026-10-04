package com.github.guoyyit.srpauthenticationjava.service;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Per-identity/source-address failure counters with lock and auto-unlock.
 * State is persisted so locks survive restarts.
 */
@Service
public class LockoutService {

    public static final class Counter {
        private int failures;
        private Instant lockedUntil;

        @JsonCreator
        public Counter(@JsonProperty("failures") int failures,
                       @JsonProperty("lockedUntil") Instant lockedUntil) {
            this.failures = failures;
            this.lockedUntil = lockedUntil;
        }

        public int getFailures() {
            return failures;
        }

        public Instant getLockedUntil() {
            return lockedUntil;
        }
    }

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path file;
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Counter> counters = new HashMap<>();

    private final PolicyProperties properties;
    private final Clock clock;

    public LockoutService(PolicyProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        this.file = Path.of(properties.getDataDir(), "locks.json");
        try {
            Files.createDirectories(file.getParent());
            if (Files.isRegularFile(file)) {
                Map<String, Counter> loaded = mapper.readValue(Files.readString(file,
                        StandardCharsets.UTF_8), new TypeReference<Map<String, Counter>>() {
                });
                counters.putAll(loaded);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open lockout store", e);
        }
    }

    private String key(String identity, String sourceAddress) {
        return identity + "|" + (sourceAddress == null ? "" : sourceAddress);
    }

    public void assertNotLocked(String identity, String sourceAddress) {
        lock.lock();
        try {
            Counter counter = counters.get(key(identity, sourceAddress));
            if (counter != null && counter.lockedUntil != null) {
                if (counter.lockedUntil.isAfter(clock.instant())) {
                    throw new ProtocolException(ErrorCode.ACCOUNT_LOCKED,
                            "identity is temporarily locked from this source address");
                }
                counter.lockedUntil = null;
                counter.failures = 0;
                persist();
            }
        } finally {
            lock.unlock();
        }
    }

    public void recordFailure(String identity, String sourceAddress) {
        lock.lock();
        try {
            Counter counter = counters.computeIfAbsent(key(identity, sourceAddress),
                    k -> new Counter(0, null));
            counter.failures++;
            if (counter.failures >= properties.getMaxFailures()) {
                counter.lockedUntil = clock.instant().plusSeconds(properties.getLockSeconds());
            }
            persist();
        } finally {
            lock.unlock();
        }
    }

    public void recordSuccess(String identity, String sourceAddress) {
        lock.lock();
        try {
            if (counters.remove(key(identity, sourceAddress)) != null) {
                persist();
            }
        } finally {
            lock.unlock();
        }
    }

    public void unlock(String identity, String sourceAddress) {
        lock.lock();
        try {
            String target = sourceAddress == null || sourceAddress.isBlank() ? null
                    : key(identity, sourceAddress);
            if (target == null) {
                counters.keySet().removeIf(k -> k.startsWith(identity + "|"));
            } else {
                counters.remove(target);
            }
            persist();
        } finally {
            lock.unlock();
        }
    }

    private void persist() {
        try {
            Path temp = Files.createTempFile(file.getParent(), "locks-", ".tmp");
            Files.writeString(temp, mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(counters), StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist lockout state", e);
        }
    }
}
