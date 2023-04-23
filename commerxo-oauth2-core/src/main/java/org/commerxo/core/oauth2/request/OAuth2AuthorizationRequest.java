package org.commerxo.core.oauth2.request;

import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.OAuth2AuthorizationResponseType;

import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public final class OAuth2AuthorizationRequest {

    private String clientId;
    private String state;
    private Set<String> scopes;
    private String redirectUri;
    private String authorizationUri;
    private AuthorizationGrantType authorizationGrantType;
    private OAuth2AuthorizationResponseType authorizationResponseType;
    private Map<String, Object> additionalParameters;

    public String getClientId() {
        return this.clientId;
    }

    public String getState() {
        return this.state;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    public AuthorizationGrantType getAuthorizationGrantType() {
        return this.authorizationGrantType;
    }

    public OAuth2AuthorizationResponseType getAuthorizationResponseType() {
        return this.authorizationResponseType;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public static Builder authorizationCode(){
        return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    public static Builder implicit(){
        return new Builder(AuthorizationGrantType.IMPLICIT);
    }

    public static Builder from(OAuth2AuthorizationRequest request){
        if(request == null)
            throw new IllegalArgumentException("");
        return new Builder(request);
    }

    public static class Builder{

        private String clientId;
        private String state;
        private Set<String> scopes;
        private String redirectUri;
        private String authorizationUri;
        private AuthorizationGrantType authorizationGrantType;
        private OAuth2AuthorizationResponseType authorizationResponseType;
        private Map<String, Object> additionalParameters;

        protected Builder(AuthorizationGrantType authorizationGrantType){
            this.authorizationGrantType = authorizationGrantType;
        }

        protected  Builder(OAuth2AuthorizationRequest request){

        }

        public Builder clientID(String clientId){
            this.clientId = clientId;
            return this;
        }

        public Builder state(String state){
            this.state = state;
            return this;
        }

        public Builder scopes(Consumer<Set<String>> scopeConsumer){
            scopeConsumer.accept(this.scopes);
            return this;
        }

        public Builder redirectUri(String redirectUri){
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder authorizationUri(String authorizationUri){
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType){
            this.authorizationGrantType = authorizationGrantType;
            return this;
        }

        public Builder authorizationResponseType(OAuth2AuthorizationResponseType authorizationResponseType){
            this.authorizationResponseType = authorizationResponseType;
            return this;
        }

        public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer){
            additionalParametersConsumer.accept(this.additionalParameters);
            return this;
        }



    }
}
