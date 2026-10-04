package com.github.guoyyit.srpauthenticationjava.storage;

import com.github.guoyyit.srpauthenticationjava.model.StoredVerifier;

import java.util.List;

/**
 * Persistent identity/verifier storage.
 */
public interface VerifierStore {

    StoredVerifier find(String identity);

    void save(StoredVerifier verifier);

    boolean exists(String identity);

    List<String> identities();
}
