package com.example.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyRequest {

    @JsonProperty("username")
    private String username;

    @JsonProperty("credentialId")
    private String credentialId;

    @JsonProperty("rawId")
    private String rawId;

    @JsonProperty("attestationObject")
    private String attestationObject;

    @JsonProperty("clientDataJSON")
    private String clientDataJSON;

    @JsonProperty("authenticatorData")
    private String authenticatorData;

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("challenge")
    private String challenge;
}
