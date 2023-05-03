package org.commerxo.authorization.server.oauth2.request;

import org.commerxo.authorization.server.oauth2.AuthorizationGrantType;
import org.commerxo.authorization.server.oauth2.OAuth2AuthorizationResponseType;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public final class OAuth2AuthorizationRequest {

    private String clientId;
    private String state;
    private Set<String> scopes;
    private String redirectUri;
    private String authorizationUri;
    private String authorizationRequestUri;
    private Map<String, Object> additionalParameters;
    private AuthorizationGrantType authorizationGrantType;
    private OAuth2AuthorizationResponseType authorizationResponseType;

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

    public String getAuthorizationRequestUri() {
        return this.authorizationRequestUri;
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

    public static Builder from(OAuth2AuthorizationRequest authorizationRequest){
        if(authorizationRequest == null)
            throw new IllegalArgumentException("OAuth2.0 authorizationRequest can't be null!");
        return new Builder()
                .clientID(authorizationRequest.getClientId())
                .state(authorizationRequest.getState())
                .scopes(s->s.addAll(authorizationRequest.getScopes()))
                .redirectUri(authorizationRequest.getRedirectUri())
                .authorizationUri(authorizationRequest.getAuthorizationUri())
                .authorizationRequestUri(authorizationRequest.getAuthorizationRequestUri())
                .authorizationGrantType(authorizationRequest.getAuthorizationGrantType())
                .authorizationResponseType(authorizationRequest.getAuthorizationResponseType())
                .additionalParameters(a -> a.putAll(authorizationRequest.getAdditionalParameters()));
    }

    public static class Builder implements Serializable {

        private String clientId;
        private String state;
        private String redirectUri;
        private String authorizationUri;
        private String authorizationRequestUri;
        private final Set<String> scopes = new HashSet<>();
        private AuthorizationGrantType authorizationGrantType;
        private OAuth2AuthorizationResponseType authorizationResponseType;
        private final Map<String, Object> additionalParameters = new HashMap<>();

        protected Builder(){}

        protected Builder(AuthorizationGrantType authorizationGrantType){
            if(authorizationGrantType == null)
                throw new IllegalArgumentException("authorizationGrantType can't be null!");
            this.authorizationGrantType = authorizationGrantType;
            if(AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
                this.authorizationResponseType = OAuth2AuthorizationResponseType.CODE;
            }

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

        public Builder authorizationRequestUri(String authorizationRequestUri){
            this.authorizationRequestUri = authorizationRequestUri;
            return this;
        }

        public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer){
            additionalParametersConsumer.accept(this.additionalParameters);
            return this;
        }


        public OAuth2AuthorizationRequest build(){
            if(!StringUtils.hasText(this.authorizationUri))
                throw new IllegalArgumentException("authorizationUri can't be empty!");
            if(!StringUtils.hasText(this.clientId))
                throw new IllegalArgumentException("clientId can't be empty!");

            OAuth2AuthorizationRequest authorizationRequest = new OAuth2AuthorizationRequest();
            authorizationRequest.clientId = this.clientId;
            authorizationRequest.redirectUri = this.redirectUri;
            authorizationRequest.state = this.state;
            authorizationRequest.scopes = this.scopes;
            authorizationRequest.authorizationUri = this.authorizationUri;
            authorizationRequest.authorizationRequestUri = this.authorizationRequestUri;
            authorizationRequest.authorizationGrantType = this.authorizationGrantType;
            authorizationRequest.authorizationResponseType = this.authorizationResponseType;
            authorizationRequest.additionalParameters = this.additionalParameters;
            return authorizationRequest;
        }

    }

}
