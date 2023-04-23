package org.commerxo.core.oauth2.client;

import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.ClientAuthenticationMethod;
import org.commerxo.core.oauth2.ClientType;
import org.commerxo.core.oauth2.id.ClientID;
import org.commerxo.core.oauth2.id.Secret;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

public interface OAuth2ClientDetails {

    ClientID getClientId();

    String getClientName();

    Secret getClientSecret();

    Instant getClientIDIssuedAt();

    Instant getClientSecretExpiredAt();

    Set<String> getRedirectUris();

    Set<String> getContacts();

    Set<String> getScopes();

    ClientType getClientType();

    Set<AuthorizationGrantType> getAuthorizationGrantTypes();

    Set<ClientAuthenticationMethod> getClientAuthenticationMethods();

    Map<String, Object> getAdditionalInformation();

}
