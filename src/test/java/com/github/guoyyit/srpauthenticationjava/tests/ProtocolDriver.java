package com.github.guoyyit.srpauthenticationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.srpauthenticationjava.client.SrpClient;
import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;
import org.springframework.http.HttpStatus;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Map;

/**
 * Minimal JSON over HTTP driver implementing the SRP client side.
 */
public class ProtocolDriver {

    public record Response(int status, String body) {
        boolean is2xx() {
            return status >= 200 && status < 300;
        }
    }

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;

    public ProtocolDriver(int port) {
        this.baseUrl = "http://localhost:" + port;
    }

    public Response post(String path, Object body, String bearer, String forwardedFor)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        if (forwardedFor != null) {
            builder.header("X-Forwarded-For", forwardedFor);
        }
        return send(builder);
    }

    public Response post(String path, Object body) throws Exception {
        return post(path, body, null, null);
    }

    public Response get(String path, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return send(builder);
    }

    private Response send(HttpRequest.Builder builder) throws Exception {
        HttpResponse<String> response = http.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.body());
    }

    public void register(String identity, char[] password) throws Exception {
        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Registration registration = client.register(identity, password, 16);
        Map<String, Object> body = Map.of(
                "identity", identity,
                "salt", Hex.encode(registration.salt()),
                "verifier", Hex.encode(toFixedWidth(registration.verifier())));
        Response response = post("/api/srp/register", body);
        if (!response.is2xx()) {
            throw new IllegalStateException("register failed: " + response.body());
        }
    }

    public record SuccessfulLogin(String token, String sessionKeyHex) {
    }

    public SuccessfulLogin login(String identity, char[] password) throws Exception {
        SrpClient client = new SrpClient(SrpParameters.defaults());
        SrpClient.Handshake handshake = client.begin();
        Map<String, Object> challengeBody = Map.of(
                "identity", identity,
                "clientPublic", Hex.encode(toFixedWidth(handshake.A())));
        Response challengeResponse = post("/api/srp/challenge", challengeBody);
        if (!challengeResponse.is2xx()) {
            throw new IllegalStateException("challenge failed: " + challengeResponse.body());
        }
        JsonNode challenge = mapper.readTree(challengeResponse.body());
        byte[] salt = Hex.decode(challenge.get("saltHex").asText());
        BigInteger serverPublic = new BigInteger(challenge.get("serverPublicHex").asText(), 16);
        SrpClient.NegotiatedKeys keys = client.finish(identity, handshake, salt,
                serverPublic, password);
        Map<String, Object> verifyBody = Map.of(
                "handshakeId", challenge.get("handshakeId").asText(),
                "clientProof", Hex.encode(keys.clientProof()));
        Response verifyResponse = post("/api/srp/verify", verifyBody);
        if (!verifyResponse.is2xx()) {
            throw new IllegalStateException("verify failed: " + verifyResponse.body());
        }
        JsonNode verify = mapper.readTree(verifyResponse.body());
        byte[] serverProof = Hex.decode(verify.get("serverProofHex").asText());
        if (!client.verifyServerProof(handshake.A(), keys.clientProof(), keys.sessionKey(),
                serverProof)) {
            throw new IllegalStateException("server proof mismatch");
        }
        return new SuccessfulLogin(verify.get("token").asText(), Hex.encode(keys.sessionKey()));
    }

    public byte[] toFixedWidth(BigInteger value) {
        int width = 256;
        byte[] raw = value.toByteArray();
        if (raw.length == width) {
            return raw;
        }
        if (raw.length == width + 1 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, raw.length);
        }
        byte[] padded = new byte[width];
        System.arraycopy(raw, 0, padded, width - raw.length, raw.length);
        return padded;
    }
}
