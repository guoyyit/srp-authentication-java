package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.config.PolicyProperties;
import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.List;
import java.util.HexFormat;
import java.util.stream.Stream;

/**
 * Filesystem-backed verifier store; each registration/rotation is written to a
 * temp file and atomically moved into place.
 */
@Component
public class FileVerifierStore implements VerifierStore {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules().disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final Path directory;

    private final PolicyProperties properties;

    public FileVerifierStore(PolicyProperties properties) {
        this.properties = properties;
        this.directory = Path.of(properties.getDataDir(), "verifiers");
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create verifier directory", e);
        }
    }

    @Override
    public StoredVerifier find(String identity) {
        Path file = pathFor(identity);
        if (!Files.isRegularFile(file)) {
            return null;
        }
        try {
            return mapper.readValue(Files.readString(file, StandardCharsets.UTF_8),
                    StoredVerifier.class);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read verifier for " + identity, e);
        }
    }

    @Override
    public void save(StoredVerifier verifier) {
        Path target = pathFor(verifier.identity());
        try {
            Path temp = Files.createTempFile(directory, "verifier-", ".tmp");
            try {
                Files.writeString(temp, mapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(verifier), StandardCharsets.UTF_8);
                try {
                    Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException atomicFailed) {
                    Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist verifier for " + verifier.identity(), e);
        }
    }

    @Override
    public boolean exists(String identity) {
        return Files.isRegularFile(pathFor(identity));
    }

    @Override
    public List<String> identities() {
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(f -> f.toString().endsWith(".json"))
                    .map(this::readIdentity)
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot list verifiers", e);
        }
    }

    private Path pathFor(String identity) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256")
                    .digest(identity.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        return directory.resolve(HexFormat.of().formatHex(digest) + ".json");
    }

    private String readIdentity(Path file) {
        try {
            return mapper.readValue(Files.readString(file, StandardCharsets.UTF_8),
                    StoredVerifier.class).identity();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + file, e);
        }
    }
}
