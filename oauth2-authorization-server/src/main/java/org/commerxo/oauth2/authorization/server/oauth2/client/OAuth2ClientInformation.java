package org.commerxo.oauth2.authorization.server.oauth2.client;

import net.minidev.json.JSONObject;
import org.commerxo.oauth2.core.id.ClientID;
import org.commerxo.oauth2.core.id.Secret;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

public class OAuth2ClientInformation {

    private final static Set<String> REGISTERED_PARAMETERS_NAME;

    static {
        Set<String> p = new HashSet<>();

        p.add("client_id");
        p.add("client_name");
        p.add("client_secret");
        p.add("client_id_issued_at");
        p.add("client_secret_expired_at");
        p.add("registration_client_uri");

        REGISTERED_PARAMETERS_NAME = p;
    }

    private ClientID clientId;
    private Secret secret;
    private Instant clientIDIssuedAt;
    private Instant clientSecretExpiredAt;
    private String clientRegisteredUri;
    private OAuth2ClientMetadata clientMetadata;

    public ClientID getClientId() {
        return this.clientId;
    }

    public void setClientId(ClientID clientId) {
        this.clientId = clientId;
    }

    public Secret getSecret() {
        return this.secret;
    }

    public void setSecret(Secret secret) {
        this.secret = secret;
    }

    public Instant getClientIDIssuedAt() {
        return this.clientIDIssuedAt;
    }

    public void setClientIDIssuedAt(Instant clientIDIssuedAt) {
        this.clientIDIssuedAt = clientIDIssuedAt;
    }

    public Instant getClientSecretExpiredAt() {
        return this.clientSecretExpiredAt;
    }

    public void setClientSecretExpiredAt(Instant clientSecretExpiredAt) {
        this.clientSecretExpiredAt = clientSecretExpiredAt;
    }

    public String getClientRegisteredUri() {
        return this.clientRegisteredUri;
    }

    public void setClientRegisteredUri(String clientRegisteredUri) {
        this.clientRegisteredUri = clientRegisteredUri;
    }

    public OAuth2ClientMetadata getClientMetadata() {
        return this.clientMetadata;
    }

    public void setClientMetadata(OAuth2ClientMetadata clientMetadata) {
        this.clientMetadata = clientMetadata;
    }


    public static Set<String> getRegisteredParametersName(){
        return REGISTERED_PARAMETERS_NAME;
    }

    public JSONObject toJSONObject(OAuth2ClientInformation clientInformation) {

        JSONObject o = OAuth2ClientMetadata.toJSONObject(clientInformation.getClientMetadata());

        if (clientInformation.getClientId() != null)
            o.put("client_id", clientInformation.getClientId().getValue());

        if (clientInformation.getClientIDIssuedAt() != null)
            o.put("client_id_issued_at", clientInformation.getClientIDIssuedAt());

        if (clientInformation.getSecret() != null)
            o.put("client_secret", clientInformation.getSecret().getValue());

        if (clientInformation.getClientSecretExpiredAt() != null)
            o.put("client_secret_expired_at", clientInformation.getClientSecretExpiredAt());

        if (clientInformation.getClientRegisteredUri() != null)
            o.put("registration_client_uri", clientInformation.getClientRegisteredUri());

        return o;
    }


}
