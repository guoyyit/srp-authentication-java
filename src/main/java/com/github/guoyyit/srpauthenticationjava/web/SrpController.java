package com.github.guoyyit.srpauthenticationjava.web;

import com.github.guoyyit.srpauthenticationjava.auth.AuditService;
import com.github.guoyyit.srpauthenticationjava.auth.LockoutService;
import com.github.guoyyit.srpauthenticationjava.auth.SrpServerService;
import com.github.guoyyit.srpauthenticationjava.session.SessionManager;
import com.github.guoyyit.srpauthenticationjava.web.dto.AuditQueryResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.ChangePasswordRequest;
import com.github.guoyyit.srpauthenticationjava.web.dto.ChangePasswordResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.HandshakeRequest;
import com.github.guoyyit.srpauthenticationjava.web.dto.HandshakeResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.RegisterRequest;
import com.github.guoyyit.srpauthenticationjava.web.dto.RegisterResponse;
import com.github.guoyyit.srpauthenticationjava.web.dto.VerifyRequest;
import com.github.guoyyit.srpauthenticationjava.web.dto.VerifyResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/srp")
public class SrpController {

    private final SrpServerService service;
    private final SessionManager sessionManager;
    private final AuditService auditService;
    private final LockoutService lockoutService;

    public SrpController(SrpServerService service,
                         SessionManager sessionManager,
                         AuditService auditService,
                         LockoutService lockoutService) {
        this.service = service;
        this.sessionManager = sessionManager;
        this.auditService = auditService;
        this.lockoutService = lockoutService;
    }

    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        requireField(request, "request body required");
        return service.register(
                request.identity,
                decodeBase64(request.salt, "salt"),
                request.verifier,
                request.digestAlgorithm,
                request.iterations);
    }

    @PostMapping("/handshake")
    public HandshakeResponse handshake(@RequestBody HandshakeRequest request,
                                       HttpServletRequest httpRequest) {
        requireField(request, "request body required");
        BigInteger clientA = request.a;
        return service.startHandshake(request.identity, clientA, sourceAddress(httpRequest));
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) {
        requireField(request, "request body required");
        return service.finishHandshake(request.sessionId, decodeBase64(request.m1, "m1"));
    }

    @PostMapping("/change-password")
    public ChangePasswordResponse changePassword(@RequestBody ChangePasswordRequest request) {
        requireField(request, "request body required");
        return service.rotateVerifier(
                request.token,
                decodeBase64(request.salt, "salt"),
                request.verifier,
                request.digestAlgorithm,
                request.iterations);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(@RequestBody Map<String, String> request) {
        String token = request == null ? null : request.get("token");
        if (token == null || token.isBlank()) {
            throw new ApiException("INVALID_TOKEN", "token is required", 400);
        }
        sessionManager.revoke(token);
        return Map.of("revoked", true);
    }

    @GetMapping("/audit")
    public AuditQueryResponse audit(@RequestParam(required = false) String identity,
                                    @RequestParam(required = false) String eventType,
                                    @RequestParam(defaultValue = "100") int limit) {
        AuditQueryResponse response = new AuditQueryResponse();
        response.events = auditService.query(identity, eventType, Math.min(limit, 1000));
        return response;
    }

    @PostMapping("/admin/unlock")
    public Map<String, Object> unlock(@RequestBody Map<String, String> request) {
        String identity = request == null ? null : request.get("identity");
        if (identity == null || identity.isBlank()) {
            throw new ApiException("INVALID_IDENTITY", "identity is required", 400);
        }
        lockoutService.unlock(identity);
        auditService.record("ADMIN_UNLOCK", identity, null, true, "manual unlock");
        return Map.of("unlocked", true, "identity", identity);
    }

    private static String sourceAddress(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static byte[] decodeBase64(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ApiException("MALFORMED_MESSAGE", field + " is required", 400);
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            throw new ApiException("MALFORMED_MESSAGE", field + " is not valid base64", 400);
        }
    }

    private static void requireField(Object request, String message) {
        if (request == null) {
            throw new ApiException("MALFORMED_MESSAGE", message, 400);
        }
    }
}
