package com.github.guoyyit.srpauthenticationjava.web.dto;

import java.math.BigInteger;

public class ChangePasswordRequest {
    public String token;
    public String salt;
    public BigInteger verifier;
    public String digestAlgorithm;
    public Integer iterations;
}
