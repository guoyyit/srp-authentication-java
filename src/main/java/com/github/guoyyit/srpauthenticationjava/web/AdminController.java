package com.github.guoyyit.srpauthenticationjava.web;

import com.github.guoyyit.srpauthenticationjava.config.PolicyService;
import com.github.guoyyit.srpauthenticationjava.model.ErrorCode;
import com.github.guoyyit.srpauthenticationjava.model.ProtocolException;
import com.github.guoyyit.srpauthenticationjava.service.LockoutService;
import com.github.guoyyit.srpauthenticationjava.storage.AuditStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Audit queries, policy updates and manual unlock.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AuditStore auditStore;
    private final PolicyService policyService;
    private final LockoutService lockoutService;

    public AdminController(AuditStore auditStore, PolicyService policyService,
                           LockoutService lockoutService) {
        this.auditStore = auditStore;
        this.policyService = policyService;
        this.lockoutService = lockoutService;
    }

    @GetMapping("/audit")
    public Object audit(@RequestParam(required = false) String type,
                        @RequestParam(required = false) String identity,
                        @RequestParam(defaultValue = "100") int limit) {
        return Map.of("events", auditStore.query(type, identity, limit));
    }

    @PostMapping("/policy")
    public Map<String, Object> policy(@RequestBody Requests.PolicyRequest request) {
        if (request.iterations != null) {
            policyService.updateIterations(request.iterations);
        }
        if (request.maxFailures != null || request.lockSeconds != null) {
            policyService.updateLockPolicy(
                    request.maxFailures == null
                            ? policyService.properties().getMaxFailures() : request.maxFailures,
                    request.lockSeconds == null
                            ? policyService.properties().getLockSeconds() : request.lockSeconds);
        }
        return Map.of(
                "iterations", policyService.properties().getIterations(),
                "maxFailures", policyService.properties().getMaxFailures(),
                "lockSeconds", policyService.properties().getLockSeconds());
    }

    @PostMapping("/unlock")
    public Map<String, Object> unlock(@RequestBody Map<String, String> request) {
        String identity = request.get("identity");
        if (identity == null || identity.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FORMAT, "identity is required");
        }
        lockoutService.unlock(identity.trim(), request.get("sourceAddress"));
        return Map.of("unlocked", true);
    }
}
