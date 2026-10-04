package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;

import java.util.List;

/**
 * Append-only, queryable audit log.
 */
public interface AuditStore {

    AuditEvent append(String type, String identity, String sourceAddress, String detail);

    List<AuditEvent> query(String type, String identity, int limit);

    List<AuditEvent> recent(int limit);
}
