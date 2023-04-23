package org.commerxo.core.oauth2.client;

import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.ClientAuthenticationMethod;
import org.commerxo.core.oauth2.ClientType;
import org.commerxo.core.oauth2.id.ClientID;
import org.commerxo.core.oauth2.id.Secret;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class OAuth2RegisteredClient implements OAuth2ClientDetails{

    private ClientID clientId;
    private String clientName;
    private Secret clientSecret;
    private ClientType clientType;
    private Set<String> contacts;
    private Set<String> scopes;
    private Set<String> redirectUris;
    private Instant clientIDIssuedAt;
    private Instant clientSecretExpiredAt;
    private Map<String, Object> additionalInformation;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;

    /*
     * Commerxo Fields
     */
    private boolean dynamicallyRegistered;

    @Override
    public ClientID getClientId() {
        return this.clientId;
    }

    @Override
    public String getClientName() {
        return this.clientName;
    }

    @Override
    public Secret getClientSecret() {
        return this.clientSecret;
    }

    @Override
    public Instant getClientIDIssuedAt() {
        return this.clientIDIssuedAt;
    }

    @Override
    public Instant getClientSecretExpiredAt() {
        return this.clientSecretExpiredAt;
    }

    @Override
    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

    @Override
    public Set<String> getContacts() {
        return this.contacts;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return this.additionalInformation;
    }

    @Override
    public ClientType getClientType() {
        return this.clientType;
    }

    @Override
    public Set<String> getScopes() {
        return this.scopes;
    }

    @Override
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return this.authorizationGrantTypes;
    }

    @Override
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return this.clientAuthenticationMethods;
    }

    public static Builder builder(){
        return new Builder();
    }

    public static Builder buildWithJson(String payload){
        return new Builder(payload);
    }

    public static Builder from(OAuth2RegisteredClient registeredClient){
        if(registeredClient == null)
            throw new IllegalArgumentException("Client Detail must not be null!");
        return new Builder(registeredClient);
    }


    public static class Builder implements Serializable {

        private ClientID clientId;
        private String clientName;
        private Secret clientSecret;
        private ClientType clientType;
        private Instant clientIDIssuedAt;
        private Instant clientSecretExpiredAt;
        private Set<String> redirectUris = new HashSet<>();
        private Set<String> contacts = new HashSet<>();
        private Set<String> scopes = new HashSet<>();
        private Map<String, Object> additionalInformation = new HashMap<>();
        private Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();

        protected Builder(){}

        protected Builder(String json){

        }

        protected Builder(OAuth2RegisteredClient registeredClient){
            this.clientId = registeredClient.getClientId();
            this.clientSecret = registeredClient.getClientSecret();
            this.clientIDIssuedAt = registeredClient.getClientIDIssuedAt();
            this.clientSecretExpiredAt = registeredClient.getClientSecretExpiredAt();
            this.clientType = registeredClient.getClientType();
            this.redirectUris = registeredClient.getRedirectUris();
            this.scopes = registeredClient.getScopes();
            this.contacts = registeredClient.getContacts();
            this.additionalInformation = registeredClient.getAdditionalInformation();
            this.authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes();
            this.clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods();
        }

        public Builder clientID(ClientID clientID){
            this.clientId = clientID;
            return this;
        }

        public Builder secret(Secret secret){
            this.clientSecret = secret;
            return this;
        }

        public Builder clientID(String clientID){
            this.clientId = new ClientID(clientID);
            return this;
        }

        public Builder secret(String secret){
            this.clientSecret = new Secret(secret);
            return this;
        }

        public Builder clientName(String clientName){
            this.clientName = clientName;
            return this;
        }

        public Builder clientType(ClientType clientType){
            this.clientType = clientType;
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

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType){
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypeConsumer){
            authorizationGrantTypeConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod){
            this.clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        public Builder clientAuthenticationMethods(Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodConsumer){
            clientAuthenticationMethodConsumer.accept(this.clientAuthenticationMethods);
            return this;
        }

        public Builder redirectUri(String redirectUri){
            this.redirectUris.add(redirectUri);
            return this;
        }

        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer){
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

        public Builder scope(String scope){
            this.scopes.add(scope);
            return this;
        }

        public Builder scopes(Consumer<Set<String>> scopeConsumer){
            scopeConsumer.accept(this.scopes);
            return this;
        }


        public Builder contact(String contact){
            this.contacts.add(contact);
            return this;
        }

        public Builder contacts(Consumer<Set<String>> contactConsumer){
            contactConsumer.accept(this.contacts);
            return this;
        }

        public Builder additionalInformation(String key, Object value){
            this.additionalInformation.put(key, value);
            return this;
        }

        public Builder additionalInformations(Consumer<Map<String, Object>> additionalInformationConsumer){
            additionalInformationConsumer.accept(this.additionalInformation);
            return this;
        }

        public OAuth2RegisteredClient build(){

            if(this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)){
                if(this.redirectUris.isEmpty()){
                    throw new IllegalArgumentException("Redirect Uri can not be empty!");
                }
            }

            if(!StringUtils.hasText(this.clientName)){
                this.clientName = this.clientId.getValue();
            }

            if (this.clientAuthenticationMethods.isEmpty()){
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.getDefault());
            }

            validateScopes();
            validateRedirectUris();
            return create();
        }

        private OAuth2RegisteredClient create(){
            OAuth2RegisteredClient registeredClient = new OAuth2RegisteredClient();
            registeredClient.clientId = this.clientId;
            registeredClient.clientName = this.clientName;
            registeredClient.scopes = this.scopes;
            registeredClient.contacts = this.contacts;
            registeredClient.clientType = this.clientType;
            registeredClient.clientSecret = this.clientSecret;
            registeredClient.redirectUris = this.redirectUris;
            registeredClient.clientIDIssuedAt = this.clientIDIssuedAt;
            registeredClient.additionalInformation = this.additionalInformation;
            registeredClient.clientSecretExpiredAt = this.clientSecretExpiredAt;
            registeredClient.authorizationGrantTypes = this.authorizationGrantTypes;
            registeredClient.clientAuthenticationMethods = this.clientAuthenticationMethods;
            return registeredClient;
        }

        private void validateScopes(){
            if(this.scopes.isEmpty()){
                return;
            }
            for(String scope:scopes){
                if(!validateScope(scope))
                    throw new IllegalArgumentException("");
            }
        }

        private static boolean validateScope(String scope){

            return true;
        }

        private void validateRedirectUris(){
            if (this.redirectUris.isEmpty()){
                return;
            }
            for (String redirectUri: this.redirectUris){
                if(!validateRedirectUri(redirectUri))
                    throw new IllegalArgumentException("Redirect Uri [ " + redirectUri + " ] is not valid redirect uri or contains fragment!");
            }
        }

        private static boolean validateRedirectUri(String redirectUri){
            try {
                URI uri = new URI(redirectUri);
                return uri.getFragment() == null;
            } catch (URISyntaxException e) {
                return false;
            }
        }

    }


}
