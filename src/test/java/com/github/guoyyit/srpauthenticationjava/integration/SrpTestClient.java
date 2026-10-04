package com.github.guoyyit.srpauthenticationjava.integration;

import com.github.guoyyit.srpauthenticationjava.crypto.SrpClient;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpCrypto;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpGroup;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal client-side helper driving the HTTP SRP flow in tests.
 */
public class SrpTestClient {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static byte[] randomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static Map<String, Object> registrationMaterial(
            String identity, String password, String digest, int iterations) {
        SrpCrypto crypto = new SrpCrypto(SrpGroup.rfc5054_2048(), digest, iterations);
        byte[] salt = randomSalt();
        byte[] x = crypto.stretchedX(identity, salt, password.toCharArray());
        BigInteger verifier = crypto.verifier(x);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity", identity);
        body.put("salt", Base64.getEncoder().encodeToString(salt));
        body.put("verifier", verifier);
        body.put("digestAlgorithm", digest);
        body.put("iterations", iterations);
        return body;
    }

    public static byte[] saltOf(Map<String, Object> body) {
        return Base64.getDecoder().decode((String) body.get("salt"));
    }

    public final SrpClient client;
    public BigInteger publicA;

    public SrpTestClient(String digest, int iterations) {
        this.client = new SrpClient(SrpGroup.rfc5054_2048(), digest, iterations, false);
        this.publicA = client.start();
    }

    public byte[] m1(String identity, String password, byte[] salt, BigInteger serverB) {
        return client.processChallenge(identity, password.toCharArray(), salt, serverB);
    }
}
