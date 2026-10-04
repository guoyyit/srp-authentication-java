package com.github.guoyyit.srpauthenticationjava.tests;

import com.github.guoyyit.srpauthenticationjava.crypto.Hex;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpEngine;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpParameters;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SrpEngineTest {

    @Test
    void rfc5054Vectors() {
        SrpEngine engine = new SrpEngine(SrpParameters.rfc5054Vector());
        String identity = "alice";
        char[] password = "password123".toCharArray();
        byte[] saltBytes = Hex.decode("BEB25379D1A8581EB5A727673A2441EE");
        BigInteger expectedX = new BigInteger("94B7555AABE9127CC58CCF4993DB6CF84D16C124", 16);
        BigInteger expectedVerifier = new BigInteger(
                "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
              + "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
              + "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
              + "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
              + "E955A5E29E7AB245DB2BE315E2099AFB", 16);
        BigInteger a = new BigInteger(
                "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393", 16);
        BigInteger b = new BigInteger(
                "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20", 16);
        BigInteger expectedA = new BigInteger(
                "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
              + "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
              + "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
              + "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
              + "B349EF5D76988A3672FAC47B0769447B", 16);
        BigInteger expectedB = new BigInteger(
                "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
              + "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
              + "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
              + "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
              + "EB4012B7D7665238A8E3FB004B117B58", 16);
        BigInteger expectedU = new BigInteger("CE38B9593487DA98554ED47D70A7AE5F462EF019", 16);
        BigInteger expectedSecret = new BigInteger(
                "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
              + "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
              + "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
              + "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
              + "C346D7E474B29EDE8A469FFECA686E5A", 16);

        BigInteger x = new BigInteger(1,
                engine.parameters().derivation().deriveX(identity, saltBytes, password));
        assertEquals(expectedX, x);

        BigInteger verifier = engine.clientPublic(x);
        assertEquals(expectedVerifier, verifier);

        assertEquals(new BigInteger("7556AA045AEF2CDD07ABAF0F665C3E818913186F", 16),
                engine.multiplierK());
        assertEquals(expectedA, engine.clientPublic(a));
        assertEquals(expectedB, engine.serverPublic(b, verifier));
        assertEquals(expectedU, engine.scramblingU(expectedA, expectedB));

        BigInteger clientS = engine.clientSecret(a, expectedA, expectedB, x, expectedU);
        BigInteger serverS = engine.serverSecret(b, expectedA, verifier, expectedU);
        assertEquals(expectedSecret, clientS);
        assertEquals(expectedSecret, serverS);

        byte[] clientKey = engine.sessionKey(clientS);
        byte[] serverKey = engine.sessionKey(serverS);
        assertTrue(SrpEngine.constantTimeEquals(clientKey, serverKey));
        assertEquals(Hex.encode(clientKey), Hex.encode(serverKey));
    }

    @Test
    void invalidEphemeralKeysRejected() {
        SrpEngine engine = new SrpEngine(SrpParameters.rfc5054Vector());
        assertThrows(IllegalArgumentException.class,
                () -> engine.validatePublic(BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> engine.validatePublic(engine.parameters().group().prime()));
    }

    @Test
    void fullHandshakeDerivesSharedSessionKey() {
        SrpEngine engine = new SrpEngine(SrpParameters.defaults());
        String identity = "bob";
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = Hex.decode("00112233445566778899AABBCCDDEEFF");
        BigInteger x = new BigInteger(1,
                engine.parameters().derivation().deriveX(identity, salt, password));
        BigInteger verifier = engine.clientPublic(x);

        BigInteger a = engine.generatePrivateKey();
        BigInteger A = engine.clientPublic(a);
        BigInteger b = engine.generatePrivateKey();
        BigInteger B = engine.serverPublic(b, verifier);
        BigInteger u = engine.scramblingU(A, B);

        byte[] clientKey = engine.sessionKey(engine.clientSecret(a, A, B, x, u));
        byte[] serverKey = engine.sessionKey(engine.serverSecret(b, A, verifier, u));
        assertTrue(SrpEngine.constantTimeEquals(clientKey, serverKey));

        byte[] m1 = engine.clientProof(identity, salt, A, B, clientKey);
        assertTrue(SrpEngine.constantTimeEquals(
                m1, engine.expectedClientProof(identity, salt, A, B, verifier, serverKey)));
        byte[] m2 = engine.serverProof(A, m1, serverKey);
        assertTrue(SrpEngine.constantTimeEquals(m2, engine.serverProof(A, m1, clientKey)));
    }
}
