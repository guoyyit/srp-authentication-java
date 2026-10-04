package com.github.guoyyit.srpauthenticationjava.crypto;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies the implementation against the published RFC 5054 Appendix B
 * test vectors (1024-bit group, SHA-1, classic SRP stretching).
 */
class Rfc5054TestVectorsTest {

    private static final String I = "alice";
    private static final char[] P = "password123".toCharArray();
    private static final byte[] SALT = hex(
            "BEB25379D1A8581EB5A727673A2441EE");

    private static final BigInteger X = new BigInteger(
            "94B7555AABE9127CC58CCF4993DB6CF84D16C124", 16);
    private static final BigInteger V = new BigInteger(
            "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
          + "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
          + "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
          + "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
          + "E955A5E29E7AB245DB2BE315E2099AFB", 16);
    private static final BigInteger A_PRIV = new BigInteger(
            "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393", 16);
    private static final BigInteger B_PRIV = new BigInteger(
            "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20", 16);
    private static final BigInteger A_PUB = new BigInteger(
            "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
          + "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
          + "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
          + "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
          + "B349EF5D76988A3672FAC47B0769447B", 16);
    private static final BigInteger B_PUB = new BigInteger(
            "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
          + "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
          + "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
          + "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
          + "EB4012B7D7665238A8E3FB004B117B58", 16);
    private static final BigInteger U = new BigInteger(
            "CE38B9593487DA98554ED47D70A7AE5F462EF019", 16);
    private static final byte[] PREMASTER = hex(
            "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
          + "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
          + "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
          + "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
          + "C346D7E474B29EDE8A469FFECA686E5A");

    private final SrpCrypto crypto =
            new SrpCrypto(SrpGroup.rfc5054_1024(), "SHA-1", 1, true);

    @Test
    void multiplierK() {
        assertEquals(new BigInteger(
                "7556AA045AEF2CDD07ABAF0F665C3E818913186F", 16), crypto.k());
    }

    @Test
    void stretchedXMatchesVector() {
        byte[] x = crypto.stretchedX(I, SALT, P);
        assertEquals(X, new BigInteger(1, x));
    }

    @Test
    void verifierMatchesVector() {
        assertEquals(V, crypto.verifier(crypto.stretchedX(I, SALT, P)));
    }

    @Test
    void publicKeysMatchVector() {
        assertEquals(A_PUB, crypto.clientPublic(A_PRIV));
        assertEquals(B_PUB, crypto.serverPublic(B_PRIV, V));
    }

    @Test
    void scramblerUMatchesVector() {
        assertEquals(U, crypto.u(A_PUB, B_PUB));
    }

    @Test
    void serverPremasterSecretMatchesVector() {
        byte[] s = crypto.serverPremaster(A_PUB, B_PRIV, U, V);
        assertArrayEquals(PREMASTER, normalize(s));
    }

    @Test
    void clientPremasterSecretMatchesVector() {
        byte[] s = crypto.clientPremaster(A_PRIV, B_PUB, U,
                crypto.stretchedX(I, SALT, P));
        assertArrayEquals(PREMASTER, normalize(s));
    }

    @Test
    void fullProofExchangeAgrees() {
        byte[] x = crypto.stretchedX(I, SALT, P);
        byte[] clientS = normalize(crypto.clientPremaster(A_PRIV, B_PUB, U, x));
        byte[] serverS = normalize(crypto.serverPremaster(A_PUB, B_PRIV, U, V));
        assertArrayEquals(clientS, serverS);
        byte[] clientKey = crypto.sessionKeyFromPremaster(clientS);
        byte[] serverKey = crypto.sessionKeyFromPremaster(serverS);
        assertArrayEquals(clientKey, serverKey);

        byte[] m1 = crypto.m1(I, SALT, A_PUB, B_PUB, clientKey);
        assertArrayEquals(m1, crypto.m1(I, SALT, A_PUB, B_PUB, serverKey));
        byte[] m2Client = crypto.m2(A_PUB, m1, clientKey);
        byte[] m2Server = crypto.m2(A_PUB, m1, serverKey);
        assertArrayEquals(m2Client, m2Server);
    }

    private static byte[] normalize(byte[] raw) {
        if (raw.length > 128 && raw[0] == 0) {
            byte[] trimmed = new byte[128];
            System.arraycopy(raw, 1, trimmed, 0, 128);
            return trimmed;
        }
        return raw;
    }

    private static byte[] hex(String value) {
        String compact = value.replaceAll("\\s+", "");
        byte[] result = new byte[compact.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(
                    compact.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }
}
