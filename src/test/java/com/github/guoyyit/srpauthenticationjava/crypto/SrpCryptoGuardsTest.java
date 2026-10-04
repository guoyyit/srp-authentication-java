package com.github.guoyyit.srpauthenticationjava.crypto;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SrpCryptoGuardsTest {

    private final SrpCrypto crypto =
            new SrpCrypto(SrpGroup.rfc5054_2048(), "SHA-256", 64);

    @Test
    void rejectsZeroNegativeAndOutOfRangeEphemerals() {
        assertTrue(crypto.isInvalidEphemeral(null));
        assertTrue(crypto.isInvalidEphemeral(BigInteger.ZERO));
        assertTrue(crypto.isInvalidEphemeral(BigInteger.valueOf(-1)));
        assertTrue(crypto.isInvalidEphemeral(crypto.getGroup().getN()));
        assertTrue(crypto.isInvalidEphemeral(crypto.getGroup().getN().add(BigInteger.ONE)));
        assertFalse(crypto.isInvalidEphemeral(BigInteger.ONE));
        assertFalse(crypto.isInvalidEphemeral(crypto.getGroup().getN().subtract(BigInteger.ONE)));
    }

    @Test
    void constantTimeComparisonHandlesLengthAndContentDifferences() {
        byte[] expected = {1, 2, 3, 4};
        assertTrue(crypto.constantTimeEquals(expected, new byte[]{1, 2, 3, 4}));
        assertFalse(crypto.constantTimeEquals(expected, new byte[]{1, 2, 3, 5}));
        assertFalse(crypto.constantTimeEquals(expected, new byte[]{1, 2, 3}));
        assertFalse(crypto.constantTimeEquals(expected, null));
        assertFalse(crypto.constantTimeEquals(null, expected));
    }

    @Test
    void rejectsZeroIterations() {
        assertThrows(IllegalArgumentException.class,
                () -> new SrpCrypto(SrpGroup.rfc5054_2048(), "SHA-256", 0));
    }
}
