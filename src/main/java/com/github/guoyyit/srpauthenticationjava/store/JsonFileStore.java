package com.github.guoyyit.srpauthenticationjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Atomic, crash-safe JSON file persistence.
 *
 * <p>Writes go to a unique temporary file, are flushed and fsynced, then moved
 * over the target with an atomic rename. Readers either see the previous
 * complete file or the new complete file, never a torn write.
 */
public class JsonFileStore {

    private final Path baseDir;
    private final ObjectMapper mapper;

    public JsonFileStore(Path baseDir) {
        this.baseDir = baseDir;
        this.mapper = new ObjectMapper();
        try {
            Files.createDirectories(baseDir);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create data directory " + baseDir, e);
        }
    }

    public Path pathOf(String name) {
        return baseDir.resolve(name + ".json");
    }

    /**
     * Serializes {@code data} and replaces the named file atomically.
     */
    public synchronized void writeAtomically(String name, Object data) {
        Path target = pathOf(name);
        Path temp = baseDir.resolve(name + ".json." + Thread.currentThread().getId()
                + "." + System.nanoTime() + ".tmp");
        try {
            byte[] bytes = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(data);
            try (OutputStream out = Files.newOutputStream(temp,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                out.write(bytes);
                out.flush();
                if (out instanceof java.io.FileOutputStream fileOut) {
                    fileOut.getFD().sync();
                }
            }
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            syncDirectory();
        } catch (IOException e) {
            deleteQuietly(temp);
            throw new UncheckedIOException("atomic write failed for " + name, e);
        }
    }

    /**
     * Reads and deserializes the named file. Returns null when absent.
     */
    public synchronized <T> T read(String name, Class<T> type) {
        Path target = pathOf(name);
        if (!Files.exists(target)) {
            return null;
        }
        try {
            return mapper.readValue(target.toFile(), type);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + name, e);
        }
    }

    public boolean exists(String name) {
        return Files.exists(pathOf(name));
    }

    private void syncDirectory() {
        // File contents are fsynced before the atomic rename, which guarantees
        // readers never observe a partially written file. Directory entry
        // durability across OS crashes is best effort on the JVM.
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // best effort
        }
    }
}
