package com.github.guoyyit.srpauthenticationjava.web;

import com.github.guoyyit.srpauthenticationjava.service.AuthService;
import com.github.guoyyit.srpauthenticationjava.service.RegistrationService;
import com.github.guoyyit.srpauthenticationjava.service.SessionService;
import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.github.guoyyit.srpauthenticationjava.config.WebConfig.authorizationToken;
import static com.github.guoyyit.srpauthenticationjava.config.WebConfig.sourceAddressOf;

/**
 * HTTP surface for registration, SRP handshake, protected resources and
 * authenticated verifier rotation.
 */
@RestController
@RequestMapping("/api/srp")
public class SrpController {

    private final RegistrationService registrationService;
    private final AuthService authService;
    private final SessionService sessionService;

    public SrpController(RegistrationService registrationService, AuthService authService,
                         SessionService sessionService) {
        this.registrationService = registrationService;
        this.authService = authService;
        this.sessionService = sessionService;
    }

    @GetMapping("/params")
    public Map<String, Object> parameters() {
        return Map.of(
                "protocol", "SRP-6a",
                "group", "rfc5054-2048",
                "digest", "SHA-256",
                "derivation", "PBKDF2",
                "iterations", registrationService.defaultIterations());
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Requests.RegisterRequest request) {
        StoredVerifier stored = registrationService.register(request.identity, request.groupId,
                request.digest, request.derivation,
                request.iterations == null ? 0 : request.iterations, request.salt,
                request.verifier);
        return Map.of("identity", stored.identity(), "version", stored.version());
    }

    @PostMapping("/challenge")
    public AuthService.ChallengeResponse challenge(@RequestBody Requests.ChallengeRequest request,
                                                   HttpServletRequest http) {
        return authService.start(request.identity, request.clientPublic, sourceAddressOf(http));
    }

    @PostMapping("/verify")
    public AuthService.VerifyResponse verify(@RequestBody Requests.VerifyRequest request,
                                             HttpServletRequest http) {
        return authService.complete(request.handshakeId, request.clientProof,
                sourceAddressOf(http));
    }

    @PostMapping("/rotate")
    public Map<String, Object> rotate(@RequestBody Requests.RotateRequest request,
                                      HttpServletRequest http) {
        authService.rotate(authorizationToken(http), request.salt, request.verifier);
        return Map.of("rotated", true);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest http) {
        String token = authorizationToken(http);
        if (StringUtils.hasText(token)) {
            sessionService.revoke(token);
        }
        return Map.of("revoked", true);
    }

    @GetMapping("/protected")
    public Map<String, Object> protectedResource(HttpServletRequest http) {
        var session = sessionService.require(authorizationToken(http));
        return Map.of("identity", session.identity(),
                "expiresAt", session.expiresAt().getEpochSecond());
    }
}
