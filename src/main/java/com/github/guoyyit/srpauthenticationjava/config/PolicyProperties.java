package com.github.guoyyit.srpauthenticationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Security policy configuration. Persisted overrides are applied by
 * {@link PolicyService} so policy changes survive restarts.
 */
@ConfigurationProperties(prefix = "srp")
public class PolicyProperties {

    private String dataDir = "data";
    private String digest = "SHA-256";
    private String derivation = "PBKDF2";
    private int iterations = 100_000;
    private int saltBytes = 16;
    private int maxFailures = 5;
    private long lockSeconds = 900;
    private long handshakeTtlSeconds = 120;
    private long sessionTtlSeconds = 3600;
    private long replayRetentionSeconds = 86_400;

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getDerivation() {
        return derivation;
    }

    public void setDerivation(String derivation) {
        this.derivation = derivation;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public int getSaltBytes() {
        return saltBytes;
    }

    public void setSaltBytes(int saltBytes) {
        this.saltBytes = saltBytes;
    }

    public int getMaxFailures() {
        return maxFailures;
    }

    public void setMaxFailures(int maxFailures) {
        this.maxFailures = maxFailures;
    }

    public long getLockSeconds() {
        return lockSeconds;
    }

    public void setLockSeconds(long lockSeconds) {
        this.lockSeconds = lockSeconds;
    }

    public long getHandshakeTtlSeconds() {
        return handshakeTtlSeconds;
    }

    public void setHandshakeTtlSeconds(long handshakeTtlSeconds) {
        this.handshakeTtlSeconds = handshakeTtlSeconds;
    }

    public long getSessionTtlSeconds() {
        return sessionTtlSeconds;
    }

    public void setSessionTtlSeconds(long sessionTtlSeconds) {
        this.sessionTtlSeconds = sessionTtlSeconds;
    }

    public long getReplayRetentionSeconds() {
        return replayRetentionSeconds;
    }

    public void setReplayRetentionSeconds(long replayRetentionSeconds) {
        this.replayRetentionSeconds = replayRetentionSeconds;
    }
}
