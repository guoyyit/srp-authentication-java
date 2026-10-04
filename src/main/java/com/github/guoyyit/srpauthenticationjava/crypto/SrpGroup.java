package com.github.guoyyit.srpauthenticationjava.crypto;

import java.math.BigInteger;

/**
 * SRP group parameters: a safe prime N and generator g.
 */
public final class SrpGroup {

    private final String id;
    private final BigInteger prime;
    private final BigInteger generator;

    public SrpGroup(String id, BigInteger prime, BigInteger generator) {
        this.id = id;
        this.prime = prime;
        this.generator = generator;
    }

    public String id() {
        return id;
    }

    public BigInteger prime() {
        return prime;
    }

    public BigInteger generator() {
        return generator;
    }

    /**
     * RFC 5054 2048-bit group.
     */
    public static SrpGroup rfc50542048() {
        String primeHex =
                "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
              + "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
              + "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
              + "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
              + "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
              + "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
              + "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
              + "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
              + "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
              + "9E4AFF73";
        return new SrpGroup("rfc5054-2048", new BigInteger(primeHex, 16), BigInteger.TWO);
    }

    /**
     * RFC 5054 1024-bit group, used only by the published standard test
     * vectors. Production handshakes use {@link #rfc50542048()}.
     */
    public static SrpGroup rfc50541024() {
        String primeHex =
                "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
              + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
              + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
              + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
              + "FD5138FE8376435B9FC61D2FC0EB06E3";
        return new SrpGroup("rfc5054-1024", new BigInteger(primeHex, 16), BigInteger.TWO);
    }
}
