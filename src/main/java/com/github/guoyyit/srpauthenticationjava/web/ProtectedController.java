package com.github.guoyyit.srpauthenticationjava.web;

import com.github.guoyyit.srpauthenticationjava.session.SessionManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demo protected resource reachable only with an unexpired, unrevoked
 * session token issued after mutual authentication.
 */
@RestController
@RequestMapping("/api/protected")
public class ProtectedController {

    private final SessionManager sessionManager;

    public ProtectedController(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @GetMapping("/ping")
    public Map<String, Object> ping(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = bearer(authorization);
        String identity = sessionManager.validate(token);
        if (identity == null) {
            throw new ApiException("INVALID_SESSION", "missing or invalid session token", 401);
        }
        return Map.of("identity", identity, "message", "authenticated");
    }

    private static String bearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        return authorization.substring("Bearer ".length()).trim();
    }
}
