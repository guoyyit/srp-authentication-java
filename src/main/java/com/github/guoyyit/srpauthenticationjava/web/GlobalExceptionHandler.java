package com.github.guoyyit.srpauthenticationjava.web;

import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps protocol failures to stable, distinguishable error envelopes.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ProtocolException.class)
    public ResponseEntity<Map<String, Object>> handleProtocol(ProtocolException error,
                                                              HttpServletRequest request) {
        return ResponseEntity.status(statusFor(error.code())).body(envelope(error.code(),
                error.getMessage(), request.getRequestURI()));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> handleMalformed(Exception error,
                                                               HttpServletRequest request) {
        return ResponseEntity.badRequest().body(envelope(ErrorCode.INVALID_FORMAT,
                "malformed request", request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception error) {
        LOG.warn("unhandled request failure", error);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(envelope(
                ErrorCode.POLICY_VIOLATION, "request could not be processed", null));
    }

    static HttpStatus statusFor(ErrorCode code) {
        return switch (code) {
            case INVALID_FORMAT, INVALID_PUBLIC_KEY, PROOF_MISMATCH, REPLAY_DETECTED,
                 POLICY_VIOLATION, IDENTITY_TAKEN -> HttpStatus.BAD_REQUEST;
            case UNAUTHORIZED, SESSION_NOT_FOUND, SESSION_EXPIRED, UNKNOWN_IDENTITY ->
                    HttpStatus.UNAUTHORIZED;
            case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
        };
    }

    private Map<String, Object> envelope(ErrorCode code, String message, String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("time", Instant.now().toString());
        body.put("code", code.name());
        body.put("message", message);
        if (path != null) {
            body.put("path", path);
        }
        return body;
    }
}
