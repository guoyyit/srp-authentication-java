package com.github.guoyyit.srpauthenticationjava.service;

import com.github.guoyyit.srpauthenticationjava.protocol.SessionInfo;
import com.github.guoyyit.srpauthenticationjava.model.AuditEvent;
import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import com.github.guoyyit.srpauthenticationjava.storage.AuditStore;
import com.github.guoyyit.srpauthenticationjava.storage.SessionTokenStore;
import org.springframework.stereotype.Service;

/**
 * Token validation and revocation for protected endpoints.
 */
@Service
public class SessionService {

    private final SessionTokenStore tokenStore;
    private final AuditStore auditStore;

    public SessionService(SessionTokenStore tokenStore, AuditStore auditStore) {
        this.tokenStore = tokenStore;
        this.auditStore = auditStore;
    }

    public SessionInfo require(String token) {
        if (token == null || token.isBlank()) {
            throw new ProtocolException(ErrorCode.UNAUTHORIZED, "missing session token");
        }
        SessionInfo info = tokenStore.validate(token.trim());
        if (info == null) {
            throw new ProtocolException(ErrorCode.SESSION_EXPIRED,
                    "session token is invalid or expired");
        }
        return info;
    }

    public void revoke(String token) {
        SessionInfo info = tokenStore.validate(token);
        tokenStore.revoke(token);
        if (info != null) {
            auditStore.append(AuditEvent.TOKEN_REVOKED, info.identity(), info.sourceAddress(),
                    null);
        }
    }
}
