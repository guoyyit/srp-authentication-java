package com.github.guoyyit.srpauthenticationjava.crypto;

/**
 * Immutable SRP parameter set: group, hash and x derivation.
 */
public record SrpParameters(SrpGroup group, String digest, XDerivation derivation) {

    public static SrpParameters defaults() {
        return of("SHA-256", "PBKDF2", 100_000);
    }

    public static SrpParameters of(String digest, String derivation, int iterations) {
        SrpGroup group = SrpGroup.rfc50542048();
        XDerivation xDerivation = "RFC2945".equalsIgnoreCase(derivation)
                ? new Rfc2945Derivation(digest)
                : new Pbkdf2Derivation(digest, iterations);
        return new SrpParameters(group, digest, xDerivation);
    }

    public static SrpParameters rfc5054Test() {
        return new SrpParameters(SrpGroup.rfc50542048(), "SHA-1",
                new Rfc2945Derivation("SHA-1"));
    }

    public static SrpParameters rfc5054Vector() {
        return new SrpParameters(SrpGroup.rfc50541024(), "SHA-1",
                new Rfc2945Derivation("SHA-1"));
    }
}
