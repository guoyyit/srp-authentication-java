package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.protocol.SessionInfo;

import java.util.List;

/**
 * Time-limited session tokens with revocation support.
 */
public interface SessionTokenStore {

    SessionInfo create(String identity, String sourceAddress);

    SessionInfo validate(String token);

    void revoke(String token);

    List<SessionInfo> active();
}
