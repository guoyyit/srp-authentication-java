package com.github.guoyyit.srpauthenticationjava.client;

import com.github.guoyyit.srpauthenticationjava.crypto.SrpEngine;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Reference SRP-6a client used for registration material generation, testing
 * and documentation. It runs entirely locally and keeps the password there.
 */
public final class SrpClient {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SrpParameters parameters;
    private final SrpEngine engine;

    public SrpClient(SrpParameters parameters) {
        this.parameters = parameters;
        this.engine = new SrpEngine(parameters);
    }

    public record Registration(byte[] salt, BigInteger verifier) {
    }

    public record Handshake(BigInteger a, BigInteger A) {
    }

    public Registration register(String identity, char[] password, byte[] salt) {
        BigInteger x = new BigInteger(1,
                parameters.derivation().deriveX(identity, salt, password));
        return new Registration(salt, engine.clientPublic(x));
    }

    public Registration register(String identity, char[] password, int saltBytes) {
        byte[] salt = new byte[saltBytes];
        RANDOM.nextBytes(salt);
        return register(identity, password, salt);
    }

    public Handshake begin() {
        BigInteger a = engine.generatePrivateKey();
        return new Handshake(a, engine.clientPublic(a));
    }

    public record NegotiatedKeys(byte[] sessionKey, byte[] clientProof) {
    }

    public NegotiatedKeys finish(String identity, Handshake handshake, byte[] salt,
                                 BigInteger serverPublic, char[] password) {
        engine.validatePublic(serverPublic);
        BigInteger x = new BigInteger(1,
                parameters.derivation().deriveX(identity, salt, password));
        BigInteger u = engine.scramblingU(handshake.A(), serverPublic);
        BigInteger secret = engine.clientSecret(handshake.a(), handshake.A(), serverPublic, x, u);
        byte[] sessionKey = engine.sessionKey(secret);
        byte[] clientProof = engine.clientProof(identity, salt, handshake.A(), serverPublic,
                sessionKey);
        return new NegotiatedKeys(sessionKey, clientProof);
    }

    public boolean verifyServerProof(BigInteger clientPublic, byte[] clientProof, byte[] sessionKey,
                                     byte[] serverProof) {
        return SrpEngine.constantTimeEquals(
                engine.serverProof(clientPublic, clientProof, sessionKey), serverProof);
    }

    public SrpEngine engine() {
        return engine;
    }
}
