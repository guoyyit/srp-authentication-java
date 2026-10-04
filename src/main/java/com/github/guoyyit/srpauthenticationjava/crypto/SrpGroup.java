package com.github.guoyyit.srpauthenticationjava.crypto;

import java.math.BigInteger;

/**
 * SRP group parameters (N, g).
 */
public final class SrpGroup {

    /**
     * Standard 2048-bit group defined in RFC 5054 Appendix A.
     */
    private static final String RFC5054_2048_HEX =
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
          + "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
          + "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
          + "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
          + "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
          + "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
          + "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
          + "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

    /**
     * Standard 1024-bit group defined in RFC 5054 Appendix A. Used by the
     * published RFC test vectors; production defaults to the 2048-bit group.
     */
    private static final String RFC5054_1024_HEX =
            "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
          + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
          + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
          + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
          + "FD5138FE8376435B9FC61D2FC0EB06E3";

    private final BigInteger n;
    private final BigInteger g;

    public SrpGroup(BigInteger n, BigInteger g) {
        this.n = n;
        this.g = g;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getG() {
        return g;
    }

    public static SrpGroup rfc5054_2048() {
        return new SrpGroup(new BigInteger(RFC5054_2048_HEX, 16), BigInteger.valueOf(2));
    }

    public static SrpGroup rfc5054_1024() {
        return new SrpGroup(new BigInteger(RFC5054_1024_HEX, 16), BigInteger.valueOf(2));
    }
}
