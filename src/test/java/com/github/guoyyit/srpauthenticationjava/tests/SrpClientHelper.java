package com.github.guoyyit.srpauthenticationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.srpauthenticationjava.client.SrpClient;
import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;

import java.math.BigInteger;
import java.util.Map;

/**
 * SRP client convenience helpers for tests.
 */
public class SrpClientHelper {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SrpClient client = new SrpClient(SrpParameters.defaults());

    public record Registration(String saltHex, String verifierHex) {
    }

    public record StartedHandshake(String handshakeId, SrpClient.Handshake handshake,
                                   byte[] salt, BigInteger serverPublic) {
    }

    public record FinishedProof(String proofHex, byte[] sessionKey) {
    }

    public Registration registration(String identity, char[] password) {
        SrpClient.Registration registration = client.register(identity, password, 16);
        return new Registration(Hex.encode(registration.salt()),
                Hex.encode(toFixedWidth(registration.verifier())));
    }

    public ProtocolDriver.Response startRaw(ProtocolDriver driver, String identity, String source)
            throws Exception {
        SrpClient.Handshake handshake = client.begin();
        return driver.post("/api/srp/challenge", Map.of(
                "identity", identity,
                "clientPublic", Hex.encode(toFixedWidth(handshake.A()))), null, source);
    }

    public StartedHandshake start(ProtocolDriver driver, String identity, String source)
            throws Exception {
        SrpClient.Handshake handshake = client.begin();
        ProtocolDriver.Response response = driver.post("/api/srp/challenge", Map.of(
                "identity", identity,
                "clientPublic", Hex.encode(toFixedWidth(handshake.A()))), null, source);
        return parse(response, handshake);
    }

    public StartedHandshake startRawHandshake(ProtocolDriver driver, String identity,
                                              String source) throws Exception {
        return start(driver, identity, source);
    }

    public FinishedProof proofWith(String identity, char[] password, StartedHandshake started) {
        SrpClient.NegotiatedKeys keys = client.finish(identity, started.handshake(),
                started.salt(), started.serverPublic(), password);
        return new FinishedProof(Hex.encode(keys.clientProof()), keys.sessionKey());
    }

    StartedHandshake parse(ProtocolDriver.Response response, SrpClient.Handshake handshake)
            throws Exception {
        JsonNode json = mapper.readTree(response.body());
        return new StartedHandshake(json.get("handshakeId").asText(), handshake,
                Hex.decode(json.get("saltHex").asText()),
                new BigInteger(json.get("serverPublicHex").asText(), 16));
    }

    private byte[] toFixedWidth(BigInteger value) {
        int width = 256;
        byte[] raw = value.toByteArray();
        if (raw.length == width) {
            return raw;
        }
        if (raw.length == width + 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        byte[] padded = new byte[width];
        System.arraycopy(raw, 0, padded, width - raw.length, raw.length);
        return padded;
    }
}
