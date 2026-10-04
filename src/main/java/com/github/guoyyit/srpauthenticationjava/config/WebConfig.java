package com.github.guoyyit.srpauthenticationjava.config;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Helpers for client source address and bearer tokens.
 */
public final class WebConfig {

    private WebConfig() {
    }

    public static String sourceAddressOf(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma < 0 ? forwarded : forwarded.substring(0, comma)).trim();
        }
        return request.getRemoteAddr();
    }

    public static String authorizationToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring("Bearer ".length()).trim();
        }
        return header;
    }
}
