package com.github.guoyyit.srpauthenticationjava.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;

import java.io.BufferedReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Records and queries audit events durably.
 *
 * <p>Events are serialized as one JSON object per line and appended to an
 * fsynced log file (O(1) writes). On startup the log is replayed line by
 * line; a torn final line left by a crash is skipped. Queries scan the
 * in-memory copy, newest first.
 */
public class AuditService {

    static final String FILE_NAME = "audit";

    private final ObjectMapper mapper = new ObjectMapper();
    private final Path logFile;
    private final List<AuditEvent> events =
            Collections.synchronizedList(new ArrayList<>());

    public AuditService(JsonFileStore fileStore) {
        this.logFile = fileStore.pathOf(FILE_NAME);
        replay();
    }

    private void replay() {
        if (!Files.exists(logFile)) {
            return;
        }
        try (BufferedReader reader = Files.newBufferedReader(logFile, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    events.add(mapper.readValue(line, AuditEvent.class));
                } catch (Exception tornLine) {
                    // A partially appended final line after a crash is ignored.
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("cannot replay audit log", e);
        }
    }

    public void record(String eventType, String identity, String sourceAddress,
                       boolean success, String detail) {
        AuditEvent event = new AuditEvent();
        event.timestamp = System.currentTimeMillis();
        event.eventType = eventType;
        event.identity = identity;
        event.sourceAddress = sourceAddress;
        event.success = success;
        event.detail = detail;
        byte[] line;
        try {
            line = (mapper.writeValueAsString(event) + System.lineSeparator())
                    .getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialize audit event", e);
        }
        synchronized (events) {
            try (OutputStream out = Files.newOutputStream(logFile,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND)) {
                out.write(line);
                out.flush();
                if (out instanceof java.io.FileOutputStream fileOut) {
                    fileOut.getFD().sync();
                }
            } catch (Exception e) {
                throw new IllegalStateException("cannot append audit event", e);
            }
            events.add(event);
        }
    }

    /**
     * Returns up to {@code limit} most recent events, optionally filtered by
     * identity and/or event type.
     */
    public List<AuditEvent> query(String identity, String eventType, int limit) {
        synchronized (events) {
            List<AuditEvent> matches = new ArrayList<>();
            for (int i = events.size() - 1; i >= 0 && matches.size() < limit; i--) {
                AuditEvent event = events.get(i);
                if (identity != null && !identity.equals(event.identity)) {
                    continue;
                }
                if (eventType != null && !eventType.equals(event.eventType)) {
                    continue;
                }
                matches.add(event);
            }
            return matches;
        }
    }
}
