package org.commerxo.core.oauth2.client;

import net.minidev.json.JSONObject;
import org.commerxo.core.oauth2.id.ClientID;
import org.commerxo.core.oauth2.id.Secret;
import org.springframework.util.StringUtils;

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
    private String clientName;
    private Instant clientIDIssuedAt;
    private Instant clientSecretExpiredAt;
    private String clientRegisteredUri;
    private OAuth2ClientMetadata clientMetadata;

    public ClientID getClientId() {
        return this.clientId;
    }

    public Secret getSecret() {
        return this.secret;
    }

    public String getClientName() {
        return this.clientName;
    }

    public Instant getClientIDIssuedAt() {
        return this.clientIDIssuedAt;
    }

    public Instant getClientSecretExpiredAt() {
        return this.clientSecretExpiredAt;
    }

    public OAuth2ClientMetadata getClientMetadata() {
        return this.clientMetadata;
    }

    public String getClientRegisteredUri() {
        return this.clientRegisteredUri;
    }

    public static Set<String> getRegisteredParametersName(){
        return REGISTERED_PARAMETERS_NAME;
    }

    public static Builder builder(){
        return new Builder();
    }

    public static Builder from(OAuth2ClientInformation clientInformation){
        if(clientInformation == null)
            throw new IllegalArgumentException("Client Information can't be null!");
        return new Builder(clientInformation);
    }

    public static JSONObject toJson(OAuth2ClientInformation clientInformation){
        if(clientInformation == null)
            throw new IllegalArgumentException("Client Information can't be null!");
        return new Builder()
                .toJSONObject(clientInformation);
    }

    public static class Builder{

        private ClientID clientId;
        private Secret secret;
        private String clientName;
        private Instant clientIDIssuedAt;
        private Instant clientSecretExpiredAt;
        private String clientRegisteredUri;
        private OAuth2ClientMetadata clientMetadata;

        protected Builder(){}

        protected Builder(OAuth2ClientInformation clientInformation){
            this.clientId = clientInformation.getClientId();
            this.secret = clientInformation.getSecret();
            this.clientName = clientInformation.getClientName();
            this.clientIDIssuedAt = clientInformation.getClientIDIssuedAt();
            this.clientSecretExpiredAt = clientInformation.getClientSecretExpiredAt();
            this.clientRegisteredUri = clientInformation.getClientRegisteredUri();
            this.clientMetadata = OAuth2ClientMetadata.from(clientInformation.getClientMetadata()).build();
        }

        public Builder clientID(String clientId){
            this.clientId = new ClientID(clientId);
            return this;
        }

        public Builder clientID(ClientID clientId){
            this.clientId = clientId;
            return this;
        }

        public Builder secret(String secret){
            this.secret = new Secret(secret);
            return this;
        }

        public Builder secret(Secret secret){
            this.secret = secret;
            return this;
        }

        public Builder clientName(String clientName){
            this.clientName = clientName;
            return this;
        }

        public Builder clientIDIssuedAt(Instant clientIDIssuedAt){
            this.clientIDIssuedAt = clientIDIssuedAt;
            return this;
        }

        public Builder clientSecretExpiredAt(Instant clientSecretExpiredAt){
            this.clientSecretExpiredAt = clientSecretExpiredAt;
            return this;
        }

        public Builder clientRegisteredUri(String clientRegisteredUri){
            this.clientRegisteredUri = clientRegisteredUri;
            return this;
        }

        public Builder clientMetadata(OAuth2ClientMetadata clientMetadata){
            this.clientMetadata = clientMetadata;
            return this;
        }

        public OAuth2ClientInformation build(){
            OAuth2ClientInformation clientInformation = new OAuth2ClientInformation();
            if(!StringUtils.hasText(this.clientName)){
                clientInformation.clientName = this.clientId.getValue();
            }
            else{
                clientInformation.clientName = this.clientName;
            }
            clientInformation.clientId = this.clientId;
            clientInformation.secret = this.secret;
            clientInformation.clientIDIssuedAt = this.clientIDIssuedAt;
            clientInformation.clientRegisteredUri = this.clientRegisteredUri;
            clientInformation.clientSecretExpiredAt = this.clientSecretExpiredAt;
            clientInformation.clientMetadata = this.clientMetadata;
            return clientInformation;
        }

        private JSONObject toJSONObject(OAuth2ClientInformation clientInformation){

            JSONObject o = OAuth2ClientMetadata.toJSON(clientInformation.getClientMetadata());

            if(clientInformation.getClientId() != null)
                o.put("client_id", clientInformation.getClientId().getValue());

            if(clientInformation.getClientName() != null)
                o.put("client_name", clientInformation.getClientName());

            if(clientInformation.getClientIDIssuedAt() != null)
                o.put("client_id_issued_at", clientInformation.getClientIDIssuedAt());

            if(clientInformation.getSecret() != null)
                o.put("client_secret", clientInformation.getSecret().getValue());

            if(clientInformation.getClientSecretExpiredAt() != null)
                o.put("client_secret_expired_at", clientInformation.getClientSecretExpiredAt());

            if(clientInformation.getClientRegisteredUri() != null)
                o.put("registration_client_uri", clientInformation.getClientRegisteredUri());

            return o;
        }

    }

}
