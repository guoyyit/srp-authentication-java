package com.github.guoyyit.srpauthenticationjava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Loads policy overrides from disk and persists runtime updates so all
 * strategy configuration survives restarts.
 */
@Service
public class PolicyService {

    private record Override(Integer iterations, Integer maxFailures, Long lockSeconds) {
    }

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path file;
    private final ReentrantLock lock = new ReentrantLock();

    private final PolicyProperties properties;

    public PolicyService(PolicyProperties properties) {
        this.properties = properties;
        this.file = Path.of(properties.getDataDir(), "policy.json");
        load();
    }

    public PolicyProperties properties() {
        return properties;
    }

    public void updateIterations(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be positive");
        }
        lock.lock();
        try {
            properties.setIterations(iterations);
            persist();
        } finally {
            lock.unlock();
        }
    }

    public void updateLockPolicy(int maxFailures, long lockSeconds) {
        if (maxFailures < 1 || lockSeconds < 0) {
            throw new IllegalArgumentException("invalid lock policy");
        }
        lock.lock();
        try {
            properties.setMaxFailures(maxFailures);
            properties.setLockSeconds(lockSeconds);
            persist();
        } finally {
            lock.unlock();
        }
    }

    private void load() {
        try {
            Files.createDirectories(file.getParent());
            if (!Files.isRegularFile(file)) {
                return;
            }
            Override override = mapper.readValue(Files.readString(file, StandardCharsets.UTF_8),
                    Override.class);
            if (override.iterations() != null) {
                properties.setIterations(override.iterations());
            }
            if (override.maxFailures() != null) {
                properties.setMaxFailures(override.maxFailures());
            }
            if (override.lockSeconds() != null) {
                properties.setLockSeconds(override.lockSeconds());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot load policy overrides", e);
        }
    }

    private void persist() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("iterations", properties.getIterations());
        values.put("maxFailures", properties.getMaxFailures());
        values.put("lockSeconds", properties.getLockSeconds());
        try {
            Path temp = Files.createTempFile(file.getParent(), "policy-", ".tmp");
            Files.writeString(temp, mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(values), StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist policy overrides", e);
        }
    }
}
