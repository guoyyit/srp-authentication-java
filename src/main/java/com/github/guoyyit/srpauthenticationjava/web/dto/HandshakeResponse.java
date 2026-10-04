package com.github.guoyyit.srpauthenticationjava.web.dto;

import java.math.BigInteger;

public class HandshakeResponse {
    public String sessionId;
    public String salt;
    public BigInteger b;
    public String digestAlgorithm;
    public Integer iterations;
}
