package com.example.keycloak;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;

import java.io.UnsupportedEncodingException;
import java.util.*;

@Path("/")
public class UserPasskeyResource {

    private final KeycloakSession session;
    private final CertPathTrustworthinessValidator certPathTrustValidator ;
    private static final Logger logger = Logger.getLogger(UserPasskeyResource.class);

    @Inject
    public UserPasskeyResource(KeycloakSession session) {
        this.session = session;
        this.certPathTrustValidator  = new NullCertPathTrustworthinessValidator();
    }

    @GET
    @Path("challenge")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge() {
        logger.info("--------------Generating WebAuthn Challenge--------------");

        // Generate a new challenge
        String challengeBase64 = generateChallenge();


        // Return the challenge as JSON response
        return Response.ok("{\"challenge\": \"" + challengeBase64 + "\"}")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @GET
    @Path("/get-credential-id")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCredentialId(@QueryParam("username") String username) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"User not found\"}")
                    .build();
        }

        // Get all WebAuthn credentials for the user
        List<CredentialModel> webAuthnCredentials = user.credentialManager()
                .getStoredCredentialsStream()
                .filter(cred -> WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(cred.getType()))
                .toList();

        if (webAuthnCredentials.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"No passkey found for user\"}")
                    .build();
        }

        // Convert the first stored credential to WebAuthnCredentialModel
        WebAuthnCredentialModel credentialModel = WebAuthnCredentialModel.createFromCredentialModel(webAuthnCredentials.get(0));

        // ✅ Get the credentialId as a byte array
        byte[] credentialId = Base64.getUrlDecoder().decode(credentialModel.getWebAuthnCredentialData().getCredentialId());

        // Convert byte[] to Base64 string
        String credentialIdBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

        // Generating a challenge
        String challengeBase64 = generateChallenge();

        // Store challenge in user attributes
        user.setSingleAttribute("webauthn-challenge", challengeBase64);

        // Return JSON response
        String jsonResponse = "{\"credentialId\": \"" + credentialIdBase64 + "\", \"challenge\": \"" + challengeBase64 + "\"}";

        return Response.ok(jsonResponse)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path("save")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response savePasskey(PasskeyRequest request) throws JsonProcessingException, UnsupportedEncodingException {
        logger.info("--------------Save passkey initiated--------------");
        if (request.getUsername() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Username and passkey are required")
                    .build();
        }

        // Get the current realm
        RealmModel realm = session.getContext().getRealm();
        List<UserModel> users = session.users()
                .searchForUserStream(realm, request.getUsername())
                .toList();

        if (users.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("User not found")
                    .build();
        }

        UserModel user = users.get(0);

        // Get the Base64-encoded clientDataJSON from the request
        String base64ClientDataJSON = request.getClientDataJSON();

        // Decode the Base64 string
        byte[] decodedBytes = Base64.getDecoder().decode(base64ClientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        // Deserialize the decoded JSON string into a JsonNode
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);


        Origin origin = new Origin(clientData.get("origin").asText());
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];

        Challenge challenge = new DefaultChallenge(clientData.get("challenge").asText());

        Set<Origin> originSet = new HashSet<>();
        originSet.add(origin);
        ServerProperty serverProperty = new ServerProperty(originSet, rpId, challenge, null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, true);

        byte[] attestationObject = Base64.getDecoder().decode(request.getAttestationObject());
        byte[] clientDataJSON = Base64.getDecoder().decode(request.getClientDataJSON());
        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);

        // Parse and validate registration data
        WebAuthnRegistrationManager webAuthnRegistrationManager = createWebAuthnRegistrationManager();
        RegistrationData registrationData = webAuthnRegistrationManager.parse(registrationRequest);
        webAuthnRegistrationManager.validate(registrationData, registrationParameters);

        // Create WebAuthn credential model input
        WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        credential.setAttestedCredentialData(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        credential.setCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        credential.setAttestationStatementFormat(registrationData.getAttestationObject().getFormat());
        credential.setTransports(registrationData.getTransports());

        WebAuthnCredentialProvider webAuthnCredProvider = (WebAuthnCredentialProvider) this.session.getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
        WebAuthnCredentialModel credentialModel = webAuthnCredProvider.getCredentialModelFromCredentialInput(credential, user.getUsername());

        // Create and store the WebAuthn credential model
        WebAuthnCredentialModel webAuthnCredentialModel = WebAuthnCredentialModel.createFromCredentialModel(credentialModel);

        // Store the credential in Keycloak
        user.credentialManager().createStoredCredential(webAuthnCredentialModel);

        return Response.status(Response.Status.CREATED)
                .entity("Passkey stored successfully")
                .build();
    }

    @POST
    @Path("authenticate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticatePasskey(PasskeyRequest request) throws UnsupportedEncodingException, JsonProcessingException {
        logger.info("--------------Authenticate passkey initiated--------------");

        RealmModel realm = session.getContext().getRealm();
        logger.info("Realm retrieved: " + realm.getName());

        // Fetch user
        UserModel user = getUserByUsername(realm, request.getUsername());
        if (user == null) {
            logger.error("User not found for username: " + request.getUsername());
            return buildErrorResponse(Response.Status.NOT_FOUND, "User not found");
        }
        logger.info("User found: " + user.getUsername());

        // Fetch WebAuthn Credential
        WebAuthnCredentialModel webAuthnCredential = getWebAuthnCredential(user, request.getCredentialId());
        if (webAuthnCredential == null) {
            logger.error("No passkey found for user: " + request.getUsername());
            return buildErrorResponse(Response.Status.NOT_FOUND, "No passkey found for user");
        }
        logger.info("Passkey found for user.");

        // Convert values before calling validation
        byte[] credentialId = decodeBase64(request.getCredentialId());
        byte[] authenticatorData = decodeBase64(request.getAuthenticatorData());
        byte[] signature = Base64Url.decode(request.getSignature());
        String clientDataJSON = request.getClientDataJSON();
        String challenge = request.getChallenge();

        logger.info("Calling isPasskeyValid...");
        boolean isValid = isPasskeyValid(credentialId, authenticatorData, clientDataJSON, signature, challenge, user, realm);

        if (isValid) {
            logger.info("Passkey validation successful.");
            return generateTokensResponse(user);
        } else {
            logger.error("Invalid passkey for user: " + request.getUsername());
            return buildErrorResponse(Response.Status.UNAUTHORIZED, "Invalid passkey");
        }
    }

    private UserModel getUserByUsername(RealmModel realm, String username) {
        return session.users().getUserByUsername(realm, username);
    }

    private WebAuthnCredentialModel getWebAuthnCredential(UserModel user, String credentialId) {
        var credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        var credList = credentials.toList();
        return (credList.get(0) != null) ? WebAuthnCredentialModel.createFromCredentialModel(credList.get(0)) : null;
    }

    private boolean isPasskeyValid(byte[] credentialId, byte[] authenticatorData, String clientDataJSON, byte[] signature, String challengeRequest, UserModel user, RealmModel realm) throws JsonProcessingException, UnsupportedEncodingException {
        // Decode the Base64 string
        byte[] decodedBytes = Base64.getDecoder().decode(clientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        String storedChallenge = user.getFirstAttribute("webauthn-challenge");
        if (storedChallenge == null || !storedChallenge.equals(challengeRequest)) {
            logger.error("Challenge mismatch or not found.");
            return false;
        }

        // Deserialize the decoded JSON string into a JsonNode
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get("origin").asText());
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];
        Challenge challenge = new DefaultChallenge(storedChallenge);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        boolean isUVFlagChecked = WebAuthnConstants.OPTION_REQUIRED.equals(realm.getWebAuthnPolicyPasswordless().getUserVerificationRequirement());
        var authReq = new AuthenticationRequest(credentialId, authenticatorData, decodeBase64(clientDataJSON), signature);
        var authParams = new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(serverProperty, isUVFlagChecked);;
        var cred = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        cred.setAuthenticationRequest(authReq);
        cred.setAuthenticationParameters(authParams);

        logger.info("credId -> " + cred.getCredentialId());
        logger.info("IS VALID --> " + user.credentialManager().isValid(cred));

        return user.credentialManager().isValid(cred);
    }

    private Response generateTokensResponse(UserModel user) {
        try {
            AccessToken token = createAccessToken(user);
            RefreshToken refreshToken = new RefreshToken(token);

            String accessTokenString = session.tokens().encode(token);
            String refreshTokenString = session.tokens().encode(refreshToken);

            return Response.ok("{\"access_token\": \"" + accessTokenString + "\", \"refresh_token\": \"" + refreshTokenString + "\"}")
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Token generation failed");
        }
    }

    private AccessToken createAccessToken(UserModel user) {
        AccessToken token = new AccessToken();
        token.setSubject(user.getId());
        token.setPreferredUsername(user.getUsername()); // Add username
        token.setEmail(user.getEmail()); // Add email if available

        AccessToken.Access realmAccess = new AccessToken.Access();
        realmAccess.addRole("user"); // Add role if needed
        token.setRealmAccess(realmAccess);

        token.exp((long) (Time.currentTime() + 300)); // Token expires in 5 minutes

        return token;
    }

    private String generateChallenge() {
        Challenge challenge = new DefaultChallenge();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
    }

    private Response buildErrorResponse(Response.Status status, String message) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("{\"error\": \"Invalid passkey\"}")
                .build();
    }

    private byte[] decodeBase64(String base64String) {
        if (base64String == null || base64String.isEmpty()) {
            return new byte[0];
        }
        return Base64.getDecoder().decode(base64String);
    }

    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager() {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new PackedAttestationStatementValidator(),
                        new TPMAttestationStatementValidator(),
                        new AndroidKeyAttestationStatementValidator(),
                        new AndroidSafetyNetAttestationStatementValidator(),
                        new FIDOU2FAttestationStatementValidator()
                ), this.certPathTrustValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(),
                new ObjectConverter()
        );
    }

}
