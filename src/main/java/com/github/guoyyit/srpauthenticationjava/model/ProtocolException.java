package com.github.guoyyit.srpauthenticationjava.model;

/**
 * A protocol-level failure mapped to a distinguishable HTTP response.
 */
public class ProtocolException extends RuntimeException {

    private final ErrorCode code;

    public ProtocolException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
