package com.github.guoyyit.srpauthenticationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configurable SRP and policy properties.
 */
@ConfigurationProperties(prefix = "srp")
public class SrpProperties {

    private String dataDir = "data";
    private String digestAlgorithm = "SHA-256";
    private int iterations = 20000;
    private int handshakeTtlSeconds = 120;
    private int sessionTtlSeconds = 3600;
    private int maxFailures = 5;
    private int lockSeconds = 900;

    public String getDataDir() { return dataDir; }
    public void setDataDir(String dataDir) { this.dataDir = dataDir; }
    public String getDigestAlgorithm() { return digestAlgorithm; }
    public void setDigestAlgorithm(String digestAlgorithm) { this.digestAlgorithm = digestAlgorithm; }
    public int getIterations() { return iterations; }
    public void setIterations(int iterations) { this.iterations = iterations; }
    public int getHandshakeTtlSeconds() { return handshakeTtlSeconds; }
    public void setHandshakeTtlSeconds(int handshakeTtlSeconds) { this.handshakeTtlSeconds = handshakeTtlSeconds; }
    public int getSessionTtlSeconds() { return sessionTtlSeconds; }
    public void setSessionTtlSeconds(int sessionTtlSeconds) { this.sessionTtlSeconds = sessionTtlSeconds; }
    public int getMaxFailures() { return maxFailures; }
    public void setMaxFailures(int maxFailures) { this.maxFailures = maxFailures; }
    public int getLockSeconds() { return lockSeconds; }
    public void setLockSeconds(int lockSeconds) { this.lockSeconds = lockSeconds; }
}
