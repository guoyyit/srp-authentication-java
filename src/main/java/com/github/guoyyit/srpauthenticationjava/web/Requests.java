package com.github.guoyyit.srpauthenticationjava.web;

/**
 * JSON request bodies.
 */
public final class Requests {

    private Requests() {
    }

    public static final class RegisterRequest {
        public String identity;
        public String groupId;
        public String digest;
        public String derivation;
        public Integer iterations;
        public String salt;
        public String verifier;
    }

    public static final class ChallengeRequest {
        public String identity;
        public String clientPublic;
    }

    public static final class VerifyRequest {
        public String handshakeId;
        public String clientProof;
    }

    public static final class RotateRequest {
        public String salt;
        public String verifier;
    }

    public static final class PolicyRequest {
        public Integer iterations;
        public Integer maxFailures;
        public Long lockSeconds;
    }
}
