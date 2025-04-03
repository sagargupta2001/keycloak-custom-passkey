package com.example.keycloak;

import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class UserPasskeyProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public UserPasskeyProvider(KeycloakSession session ) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new UserPasskeyResource(session);
    }

    @Override
    public void close() {
    }
}
