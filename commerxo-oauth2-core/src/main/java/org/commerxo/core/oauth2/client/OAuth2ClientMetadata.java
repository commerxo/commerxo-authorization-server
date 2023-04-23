package org.commerxo.core.oauth2.client;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONArray;
import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.ClientAuthenticationMethod;
import org.commerxo.core.oauth2.ClientType;
import org.commerxo.core.oauth2.id.SoftwareID;
import org.commerxo.core.oauth2.id.SoftwareVersion;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class OAuth2ClientMetadata {

    private JWKSet jwkSet;
    private String jwksUri;
    private String clientUri;
    private String logoUri;
    private String tosUri;
    private String policyUri;
    private ClientType clientType;
    private Set<String> contacts;
    private Set<String> scopes;
    private SoftwareID softwareID;
    private SoftwareVersion softwareVersion;
    private Set<String> redirectUris;
    private SignedJWT softwareStatement;
    private Set<AuthorizationGrantType> grantTypes;
    private ClientAuthenticationMethod clientAuthenticationMethod;
    private JWSAlgorithm clientAuthenticationAlg;
    private Map<String, Object> additionalInformation;


    public JWKSet getJwkSet() {
        return this.jwkSet;
    }

    public String getJwksUri() {
        return this.jwksUri;
    }

    public String getClientUri() {
        return this.clientUri;
    }

    public String getLogoUri() {
        return this.logoUri;
    }

    public String getTosUri() {
        return this.tosUri;
    }

    public String getPolicyUri() {
        return this.policyUri;
    }

    public ClientType getClientType() {
        return this.clientType;
    }

    public Set<String> getContacts() {
        return this.contacts;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public SoftwareID getSoftwareID() {
        return this.softwareID;
    }

    public SoftwareVersion getSoftwareVersion() {
        return this.softwareVersion;
    }

    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

    public SignedJWT getSoftwareStatement() {
        return this.softwareStatement;
    }

    public Map<String, Object> getAdditionalInformation() {
        return this.additionalInformation;
    }

    public Set<AuthorizationGrantType> getGrantTypes() {
        return this.grantTypes;
    }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return this.clientAuthenticationMethod;
    }

    public JWSAlgorithm getClientAuthenticationAlg() {
        return this.clientAuthenticationAlg;
    }

    public static Builder builder(){
        return new Builder();
    }

    public static Builder from(OAuth2ClientMetadata clientMetadata){
        if(clientMetadata == null)
            throw new IllegalArgumentException("Client Metadata can't be null!");
        return new Builder(clientMetadata);
    }

    public static JSONObject toJSON(OAuth2ClientMetadata clientMetadata){
        if(clientMetadata == null)
            throw new IllegalArgumentException("Client Metadata can't be null!");
        return new Builder()
                .toJSONObject(clientMetadata);
    }

    public static class Builder{

        private JWKSet jwkSet;
        private String jwksUri;
        private String clientUri;
        private String logoUri;
        private String tosUri;
        private String policyUri;
        private ClientType clientType;
        private SoftwareID softwareID;
        private SoftwareVersion softwareVersion;
        private SignedJWT softwareStatement;
        private final Map<String, Object> additionalInformations = new HashMap<>();
        private final Set<AuthorizationGrantType> grantTypes = new HashSet<>();
        private final Set<String> contacts = new HashSet<>();
        private final Set<String> scopes = new HashSet<>();
        private final Set<String> redirectUris = new HashSet<>();
        private ClientAuthenticationMethod clientAuthenticationMethod;
        private JWSAlgorithm clientAuthenticationAlg;

        protected Builder(){}

        protected Builder(OAuth2ClientMetadata clientMetadata){
            this.jwkSet = clientMetadata.getJwkSet();
            this.jwksUri = clientMetadata.getJwksUri();
            this.clientUri = clientMetadata.getClientUri();
            this.logoUri = clientMetadata.getLogoUri();
            this.tosUri = clientMetadata.getTosUri();
            this.policyUri = clientMetadata.getPolicyUri();
            this.clientType = clientMetadata.getClientType();
            this.softwareID = clientMetadata.getSoftwareID();
            this.softwareVersion = clientMetadata.getSoftwareVersion();
            this.softwareStatement = clientMetadata.getSoftwareStatement();
            if(!clientMetadata.getGrantTypes().isEmpty()){
                this.grantTypes.addAll(clientMetadata.getGrantTypes());
            }
            if(!clientMetadata.getContacts().isEmpty()){
                this.contacts.addAll(clientMetadata.getContacts());
            }
            if(!clientMetadata.getScopes().isEmpty()){
                this.scopes.addAll(clientMetadata.getScopes());
            }
            if(!clientMetadata.getRedirectUris().isEmpty()){
                this.redirectUris.addAll(clientMetadata.getRedirectUris());
            }
            if(!clientMetadata.getAdditionalInformation().isEmpty()){
                this.additionalInformations.putAll(clientMetadata.getAdditionalInformation());
            }
            this.clientAuthenticationMethod = clientMetadata.getClientAuthenticationMethod();
            this.clientAuthenticationAlg = clientMetadata.getClientAuthenticationAlg();
        }

        public Builder jwkSet(JWKSet jwkSet){
            this.jwkSet = jwkSet;
            return this;
        }

        public Builder jwksUri(String jwksUri){
            this.jwksUri = jwksUri;
            return this;
        }

        public Builder softwareID(SoftwareID softwareID){
            this.softwareID = softwareID;
            return this;
        }

        public Builder softwareID(String softwareID){
            this.softwareID = new SoftwareID(softwareID);
            return this;
        }

        public Builder softwareVersion(String softwareVersion){
            this.softwareVersion = new SoftwareVersion(softwareVersion);
            return this;
        }

        public Builder clientUri(String clientUri){
            this.clientUri = clientUri;
            return this;
        }

        public Builder logoUri(String logoUri){
            this.logoUri = logoUri;
            return this;
        }

        public Builder tosUri(String tosUri){
            this.tosUri = tosUri;
            return this;
        }

        public Builder policyUri(String policyUri){
            this.policyUri = policyUri;
            return this;
        }

        public Builder clientType(ClientType clientType){
            this.clientType = clientType;
            return this;
        }

        public Builder contact(String contact){
            this.contacts.add(contact);
            return this;
        }

        public Builder contacts(Consumer<Set<String>> contactsConsumer){
            contactsConsumer.accept(this.contacts);
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

        public Builder redirectUri(String redirectUri){
            this.redirectUris.add(redirectUri);
            return this;
        }

        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer){
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

        public Builder grantType(AuthorizationGrantType grantType){
            this.grantTypes.add(grantType);
            return this;
        }

        public Builder grantTypes(Consumer<Set<AuthorizationGrantType>> grantTypeConsumer){
            grantTypeConsumer.accept(this.grantTypes);
            return this;
        }

        public Builder softwareStatement(SignedJWT softwareStatement){
            this.softwareStatement = softwareStatement;
            return this;
        }

        public Builder additionalInformation(String key, String value){
            this.additionalInformations.put(key, value);
            return this;
        }

        public Builder additionalInformations(Consumer<Map<String, Object>> additionalInformationsConsumer){
            additionalInformationsConsumer.accept(this.additionalInformations);
            return this;
        }

        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod){
            this.clientAuthenticationMethod = clientAuthenticationMethod;
            return this;
        }

        public Builder clientAuthenticationAlg(JWSAlgorithm clientAuthenticationAlg){
            this.clientAuthenticationAlg = clientAuthenticationAlg;
            return this;
        }

        public OAuth2ClientMetadata build(){
            if(this.grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)){
                if(this.redirectUris.isEmpty())
                    throw new IllegalArgumentException("RedirectUri can't be empty!");
            }

            if(this.clientAuthenticationMethod == null){
                this.clientAuthenticationMethod = ClientAuthenticationMethod.getDefault();
            }
            return create();
        }

        private OAuth2ClientMetadata create(){
            OAuth2ClientMetadata clientMetadata = new OAuth2ClientMetadata();
            clientMetadata.jwkSet = this.jwkSet;
            clientMetadata.jwksUri = this.jwksUri;
            clientMetadata.clientUri = this.clientUri;
            clientMetadata.logoUri = this.logoUri;
            clientMetadata.tosUri = this.tosUri;
            clientMetadata.policyUri = this.policyUri;
            clientMetadata.clientType = this.clientType;
            clientMetadata.softwareID = this.softwareID;
            clientMetadata.softwareVersion = this.softwareVersion;
            clientMetadata.softwareStatement = this.softwareStatement;
            clientMetadata.additionalInformation = this.additionalInformations;
            clientMetadata.grantTypes = this.grantTypes;
            clientMetadata.contacts = this.contacts;
            clientMetadata.redirectUris = this.redirectUris;
            clientMetadata.scopes = this.scopes;
            clientMetadata.clientAuthenticationAlg = this.clientAuthenticationAlg;
            clientMetadata.clientAuthenticationMethod = this.clientAuthenticationMethod;
            return clientMetadata;
        }

        private JSONObject toJSONObject(OAuth2ClientMetadata clientMetadata){
            JSONObject o = new JSONObject();

            if(clientMetadata.getJwkSet() != null)
                o.put("jwk_set", clientMetadata.getJwkSet().toString());

            if(!clientMetadata.getRedirectUris().isEmpty())
                o.put("redirect_uris", clientMetadata.getRedirectUris());

            if(clientMetadata.getJwksUri() != null)
                o.put("jwks_uri", clientMetadata.getJwksUri());

            if(clientMetadata.getClientUri() != null)
                o.put("client_uri", clientMetadata.getClientUri());

            if(clientMetadata.getLogoUri() != null)
                o.put("logo_uri", clientMetadata.getLogoUri());

            if(clientMetadata.getTosUri() != null)
                o.put("tos_uri", clientMetadata.getTosUri());

            if(clientMetadata.getPolicyUri() != null)
                o.put("policy_uri", clientMetadata.getPolicyUri());

            if(clientMetadata.getClientType() != null)
                o.put("client_type", clientMetadata.getClientType().getValue());

            if(clientMetadata.getSoftwareID() != null)
                o.put("software_id", clientMetadata.getSoftwareID().getValue());

            if(clientMetadata.getSoftwareVersion() != null)
                o.put("software_version", clientMetadata.getSoftwareVersion().getValue());

            if(clientMetadata.getSoftwareStatement() != null)
                o.put("software_statement", clientMetadata.getSoftwareStatement().serialize());

            if(!clientMetadata.getGrantTypes().isEmpty()){
                JSONArray grantList = new JSONArray();

                for (AuthorizationGrantType grantType: clientMetadata.getGrantTypes()){
                    grantList.add(grantType.getValue());
                }

                o.put("grant_types", grantList);
            }

            if(!clientMetadata.getContacts().isEmpty())
                o.put("contacts", clientMetadata.getContacts());

            if(!clientMetadata.getScopes().isEmpty())
                o.put("scopes", clientMetadata.getScopes());

            if(clientMetadata.getClientAuthenticationAlg() != null)
                o.put("token_endpoint_auth_signing_alg", clientMetadata.getClientAuthenticationAlg().getName());

            if(clientMetadata.getClientAuthenticationMethod() != null)
                o.put("token_endpoint_auth_method", clientMetadata.getClientAuthenticationMethod().getValue());

            return o;
        }
    }
}
