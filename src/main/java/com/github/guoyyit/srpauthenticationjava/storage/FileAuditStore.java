package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only JSON-lines audit log, durable and queryable after restart.
 */
@Component
public class FileAuditStore implements AuditStore {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path file;
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicLong lastId = new AtomicLong();

    private final PolicyProperties properties;

    public FileAuditStore(PolicyProperties properties) {
        this.properties = properties;
        this.file = Path.of(properties.getDataDir(), "audit.jsonl");
        try {
            Files.createDirectories(file.getParent());
            if (Files.notExists(file)) {
                Files.createFile(file);
            }
            for (AuditEvent event : readAll()) {
                if (event.id() > lastId.get()) {
                    lastId.set(event.id());
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open audit log", e);
        }
    }

    @Override
    public AuditEvent append(String type, String identity, String sourceAddress, String detail) {
        lock.lock();
        try {
            AuditEvent event = new AuditEvent(lastId.incrementAndGet(), Instant.now(), type,
                    identity, sourceAddress, detail);
            String line = mapper.writeValueAsString(event);
            Files.writeString(file, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.APPEND);
            return event;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot append audit event", e);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<AuditEvent> query(String type, String identity, int limit) {
        int bounded = Math.max(1, Math.min(limit, 1000));
        ArrayDeque<AuditEvent> matches = new ArrayDeque<>();
        for (AuditEvent event : readAll()) {
            if (type != null && !type.isBlank() && !type.equals(event.type())) {
                continue;
            }
            if (identity != null && !identity.isBlank() && !identity.equals(event.identity())) {
                continue;
            }
            matches.addLast(event);
            if (matches.size() > bounded) {
                matches.removeFirst();
            }
        }
        return new ArrayList<>(matches);
    }

    @Override
    public List<AuditEvent> recent(int limit) {
        return query(null, null, limit);
    }

    private List<AuditEvent> readAll() {
        try {
            List<AuditEvent> events = new ArrayList<>();
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    events.add(mapper.readValue(line, AuditEvent.class));
                }
            }
            return events;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read audit log", e);
        }
    }
}
