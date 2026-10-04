package com.github.guoyyit.srpauthenticationjava.model;

/**
 * Issued authenticated session token record.
 */
public class SessionRecord {

    public String token;
    public String identity;
    public long issuedAt;
    public long expiresAt;
    public boolean revoked;

    public SessionRecord() {
    }
}
