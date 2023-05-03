package org.commerxo.oauth2.authorization.server.oauth2.client;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.commerxo.oauth2.core.AuthorizationGrantType;
import org.commerxo.oauth2.core.ClientAuthenticationMethod;
import org.commerxo.oauth2.core.ClientType;
import org.commerxo.oauth2.core.id.SoftwareID;
import org.commerxo.oauth2.core.id.SoftwareVersion;

import java.util.Map;
import java.util.Set;

public class OAuth2ClientMetadata {

    private String clientName;
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

    public void setJwkSet(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    public String getClientName() {
        return this.clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getJwksUri() {
        return this.jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getClientUri() {
        return this.clientUri;
    }

    public void setClientUri(String clientUri) {
        this.clientUri = clientUri;
    }

    public String getLogoUri() {
        return this.logoUri;
    }

    public void setLogoUri(String logoUri) {
        this.logoUri = logoUri;
    }

    public String getTosUri() {
        return this.tosUri;
    }

    public void setTosUri(String tosUri) {
        this.tosUri = tosUri;
    }

    public String getPolicyUri() {
        return this.policyUri;
    }

    public void setPolicyUri(String policyUri) {
        this.policyUri = policyUri;
    }

    public ClientType getClientType() {
        return this.clientType;
    }

    public void setClientType(ClientType clientType) {
        this.clientType = clientType;
    }

    public Set<String> getContacts() {
        return this.contacts;
    }

    public void setContacts(Set<String> contacts) {
        this.contacts = contacts;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public SoftwareID getSoftwareID() {
        return this.softwareID;
    }

    public void setSoftwareID(SoftwareID softwareID) {
        this.softwareID = softwareID;
    }

    public SoftwareVersion getSoftwareVersion() {
        return this.softwareVersion;
    }

    public void setSoftwareVersion(SoftwareVersion softwareVersion) {
        this.softwareVersion = softwareVersion;
    }

    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

    public void setRedirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public SignedJWT getSoftwareStatement() {
        return this.softwareStatement;
    }

    public void setSoftwareStatement(SignedJWT softwareStatement) {
        this.softwareStatement = softwareStatement;
    }

    public Set<AuthorizationGrantType> getGrantTypes() {
        return this.grantTypes;
    }

    public void setGrantTypes(Set<AuthorizationGrantType> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return this.clientAuthenticationMethod;
    }

    public void setClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
        this.clientAuthenticationMethod = clientAuthenticationMethod;
    }

    public JWSAlgorithm getClientAuthenticationAlg() {
        return this.clientAuthenticationAlg;
    }

    public void setClientAuthenticationAlg(JWSAlgorithm clientAuthenticationAlg) {
        this.clientAuthenticationAlg = clientAuthenticationAlg;
    }

    public Map<String, Object> getAdditionalInformation() {
        return this.additionalInformation;
    }

    public void setAdditionalInformation(Map<String, Object> additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    public static JSONObject toJSONObject(OAuth2ClientMetadata clientMetadata) {
        JSONObject o = new JSONObject();

        if (clientMetadata.getClientName() != null)
            o.put("client_name", clientMetadata.getClientName());

        if (clientMetadata.getJwkSet() != null)
            o.put("jwk_set", clientMetadata.getJwkSet().toString());

        if (!clientMetadata.getRedirectUris().isEmpty())
            o.put("redirect_uris", clientMetadata.getRedirectUris());

        if (clientMetadata.getJwksUri() != null)
            o.put("jwks_uri", clientMetadata.getJwksUri());

        if (clientMetadata.getClientUri() != null)
            o.put("client_uri", clientMetadata.getClientUri());

        if (clientMetadata.getLogoUri() != null)
            o.put("logo_uri", clientMetadata.getLogoUri());

        if (clientMetadata.getTosUri() != null)
            o.put("tos_uri", clientMetadata.getTosUri());

        if (clientMetadata.getPolicyUri() != null)
            o.put("policy_uri", clientMetadata.getPolicyUri());

        if (clientMetadata.getClientType() != null)
            o.put("client_type", clientMetadata.getClientType().getValue());

        if (clientMetadata.getSoftwareID() != null)
            o.put("software_id", clientMetadata.getSoftwareID().getValue());

        if (clientMetadata.getSoftwareVersion() != null)
            o.put("software_version", clientMetadata.getSoftwareVersion().getValue());

        if (clientMetadata.getSoftwareStatement() != null)
            o.put("software_statement", clientMetadata.getSoftwareStatement().serialize());

        if (!clientMetadata.getGrantTypes().isEmpty()) {
            JSONArray grantList = new JSONArray();

            for (AuthorizationGrantType grantType : clientMetadata.getGrantTypes()) {
                grantList.add(grantType.getValue());
            }

            o.put("grant_types", grantList);
        }

        if (!clientMetadata.getContacts().isEmpty())
            o.put("contacts", clientMetadata.getContacts());

        if (!clientMetadata.getScopes().isEmpty())
            o.put("scopes", clientMetadata.getScopes());

        if (clientMetadata.getClientAuthenticationAlg() != null)
            o.put("token_endpoint_auth_signing_alg", clientMetadata.getClientAuthenticationAlg().getName());

        if (clientMetadata.getClientAuthenticationMethod() != null)
            o.put("token_endpoint_auth_method", clientMetadata.getClientAuthenticationMethod().getValue());

        return o;
    }

}
