package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.protocol.SessionInfo;
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
import java.time.Instant;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Session token store; tokens survive a crash while remaining time-limited and
 * revocable.
 */
@Component
public class PersistentSessionTokenStore implements SessionTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path file;
    private final ReentrantLock fileLock = new ReentrantLock();
    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();

    private final PolicyProperties properties;
    private final Clock clock;

    public PersistentSessionTokenStore(PolicyProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        this.file = Path.of(properties.getDataDir(), "sessions.json");
        try {
            Files.createDirectories(file.getParent());
            if (Files.isRegularFile(file)) {
                List<SessionInfo> loaded = mapper.readValue(Files.readString(file,
                        StandardCharsets.UTF_8), new TypeReference<List<SessionInfo>>() {
                });
                for (SessionInfo info : loaded) {
                    sessions.put(info.token(), info);
                }
            }
            pruneExpired();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open session store", e);
        }
    }

    @Override
    public SessionInfo create(String identity, String sourceAddress) {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String token = Hex.encode(raw);
        Instant now = clock.instant();
        SessionInfo info = new SessionInfo(token, identity, sourceAddress, now,
                now.plusSeconds(properties.getSessionTtlSeconds()));
        sessions.put(token, info);
        persist();
        return info;
    }

    @Override
    public SessionInfo validate(String token) {
        SessionInfo info = token == null ? null : sessions.get(token);
        if (info == null) {
            return null;
        }
        if (!info.expiresAt().isAfter(clock.instant())) {
            sessions.remove(token);
            persist();
            return null;
        }
        return info;
    }

    @Override
    public void revoke(String token) {
        if (sessions.remove(token) != null) {
            persist();
        }
    }

    @Override
    public List<SessionInfo> active() {
        pruneExpired();
        return new ArrayList<>(sessions.values());
    }

    private void pruneExpired() {
        Instant now = clock.instant();
        boolean changed = false;
        for (SessionInfo info : new ArrayList<>(sessions.values())) {
            if (!info.expiresAt().isAfter(now)) {
                sessions.remove(info.token());
                changed = true;
            }
        }
        if (changed) {
            persist();
        }
    }

    private void persist() {
        fileLock.lock();
        try {
            Path temp = Files.createTempFile(file.getParent(), "sessions-", ".tmp");
            Files.writeString(temp, mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(new ArrayList<>(sessions.values())), StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist sessions", e);
        } finally {
            fileLock.unlock();
        }
    }
}
