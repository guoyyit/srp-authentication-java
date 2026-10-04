package com.github.guoyyit.srpauthenticationjava.model;

/**
 * Immutable audit record.
 */
public class AuditEvent {

    public long timestamp;
    public String eventType;
    public String identity;
    public String sourceAddress;
    public String detail;
    public boolean success;

    public AuditEvent() {
    }
}
