package org.commerxo.core.oauth2.client;

import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.ClientAuthenticationMethod;
import org.commerxo.core.oauth2.ClientType;
import org.commerxo.core.oauth2.id.ClientID;
import org.commerxo.core.oauth2.id.Secret;
import org.junit.jupiter.api.Test;
import net.minidev.json.JSONObject;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class OAuth2RegisteredClientTest {

    private static final Set<String> REDIRECT_URIS = Set.of("https://www.example.com","http://www.example1.com");
    private static final Set<String> SCOPES = Set.of("email:read", "profile:read");
    private static final Set<ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHODS = Set.of(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
    private static final Set<AuthorizationGrantType> AUTHORIZATION_GRANT_TYPES = Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIAL);

    @Test
    public void testRegisteredClientWhenClientIDNullAndThrowsException() throws Exception{
        assertThrows(IllegalArgumentException.class, ()->{
            OAuth2RegisteredClient.builder()
                    .clientID((String) null)
                    .build();
        });
    }

    @Test
    public void testRegisteredClientWhenSecretIDNullAndThrowsException() throws Exception{
        assertThrows(IllegalArgumentException.class, ()->{
            OAuth2RegisteredClient.builder()
                    .clientID("client")
                    .secret((String) null)
                    .build();
        });
    }

    @Test
    public void testRegisteredClientWhenRedirectUriNotProvidedForAuthorizationCode() throws Exception{
        assertThrows(IllegalArgumentException.class, () -> {OAuth2RegisteredClient.builder()
                .clientID(new ClientID("client"))
                .secret(new Secret("secret"))
                .clientAuthenticationMethods(c ->  c.addAll(CLIENT_AUTHENTICATION_METHODS))
                .authorizationGrantTypes( g -> g.addAll(AUTHORIZATION_GRANT_TYPES))
                .build();
        });
    }

    @Test
    public void testRegisteredClientWhenClientAuthenticationMethodNotProvided() throws Exception{
        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClient.builder()
                .clientID(new ClientID("client"))
                .secret(new Secret("secret"))
                .build();
        assertEquals("client", registeredClient.getClientId().getValue());
        assertEquals("secret", registeredClient.getClientSecret().getValue());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), registeredClient.getClientAuthenticationMethods());
    }

    @Test
    public void testRegisteredClientWhenNotProvidingClientIDAndSecret() throws Exception{
        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClient.builder()
                .clientID(new ClientID())
                .secret(new Secret())
                .build();
        assertNotNull(registeredClient.getClientId());
        assertNotNull(registeredClient.getClientSecret());
    }


    @Test
    public void testRegisteredClientWhenAllAttributesAreSet() throws Exception{
        Instant clientIDIssuedAt = Instant.now();
        Instant clientSecretExpiredAt = clientIDIssuedAt.plus(5, ChronoUnit.MINUTES);

        OAuth2ClientMetadata clientMetadata = OAuth2ClientMetadata.builder()
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUris(r -> r.addAll(REDIRECT_URIS))
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .grantType(AuthorizationGrantType.CLIENT_CREDENTIAL)
                .build();

        OAuth2ClientInformation clientInformation = OAuth2ClientInformation.builder()
                .clientID("client")
                .secret("secret")
                .clientMetadata(clientMetadata)
                .build();

        JSONObject json = OAuth2ClientInformation.toJson(clientInformation);

        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClient.builder()
                .clientID("client")
                .secret("secret")
                .clientIDIssuedAt(clientIDIssuedAt)
                .clientSecretExpiredAt(clientSecretExpiredAt)
                .redirectUris(r -> r.addAll(REDIRECT_URIS))
                .scopes(s -> s.addAll(SCOPES))
                .clientType(ClientType.CONFIDENTIAL)
                .clientName("client")
                .clientAuthenticationMethods(c -> c.addAll(CLIENT_AUTHENTICATION_METHODS))
                .authorizationGrantTypes(grantType -> grantType.addAll(AUTHORIZATION_GRANT_TYPES))
                .contacts(contact -> contact.add("exampleId@example.com"))
                .additionalInformations(information ->  information.put("key1", "value1"))
                .build();


        assertEquals("client", registeredClient.getClientId().getValue());
        assertEquals("secret", registeredClient.getClientSecret().getValue());
        assertEquals(clientIDIssuedAt, registeredClient.getClientIDIssuedAt());
        assertEquals(clientSecretExpiredAt, registeredClient.getClientSecretExpiredAt());
        assertEquals(REDIRECT_URIS, registeredClient.getRedirectUris());
        assertEquals(SCOPES, registeredClient.getScopes());
        assertEquals(ClientType.CONFIDENTIAL, registeredClient.getClientType());
        assertEquals("client", registeredClient.getClientName());
        assertEquals(CLIENT_AUTHENTICATION_METHODS, registeredClient.getClientAuthenticationMethods());
        assertEquals(AUTHORIZATION_GRANT_TYPES, registeredClient.getAuthorizationGrantTypes());
        assertEquals(Set.of("exampleId@example.com"), registeredClient.getContacts());
        assertEquals(Map.of("key1", "value1"), registeredClient.getAdditionalInformation());
    }

    @Test
    public void testRegisteredClient() throws Exception{
        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClientTest
                .getRegisteredClient()
                .build();
        assertEquals("client", registeredClient.getClientId().getValue());
        assertEquals("secret", registeredClient.getClientSecret().getValue());
        assertTrue(registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        assertEquals(REDIRECT_URIS, registeredClient.getRedirectUris());
        assertEquals(SCOPES, registeredClient.getScopes());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), registeredClient.getClientAuthenticationMethods());
        assertEquals(ClientType.CONFIDENTIAL, registeredClient.getClientType());
        assertEquals(Set.of("exampleId@example.com"), registeredClient.getContacts());
        assertEquals(Map.of("key1", "value1"), registeredClient.getAdditionalInformation());
    }

    @Test
    public void testRegisteredClient2() throws Exception{
        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClientTest
                .getRegisteredClient2()
                .build();
        assertEquals("client", registeredClient.getClientId().getValue());
        assertEquals("secret", registeredClient.getClientSecret().getValue());
        assertTrue(registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        assertEquals(Set.of("https://www.example.com"), registeredClient.getRedirectUris());
        assertEquals(Set.of("profile:read"), registeredClient.getScopes());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), registeredClient.getClientAuthenticationMethods());
        assertEquals(ClientType.CONFIDENTIAL, registeredClient.getClientType());
        assertEquals(Set.of("exampleId@example.com"), registeredClient.getContacts());
        assertEquals(Map.of("key1", "value1"), registeredClient.getAdditionalInformation());
    }

    @Test
    public void testUpdateRegisteredClientWhenMakeCopy() throws Exception{
        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClientTest.getRegisteredClient().build();
        OAuth2RegisteredClient updatedClient = OAuth2RegisteredClient.from(registeredClient).build();

        assertEquals(registeredClient.getClientId().getValue(), updatedClient.getClientId().getValue());
        assertEquals(registeredClient.getClientIDIssuedAt(), updatedClient.getClientIDIssuedAt());
        assertEquals(registeredClient.getClientSecretExpiredAt(), updatedClient.getClientSecretExpiredAt());
        assertEquals(registeredClient.getAuthorizationGrantTypes(), updatedClient.getAuthorizationGrantTypes());
        assertEquals(registeredClient.getClientAuthenticationMethods(), updatedClient.getClientAuthenticationMethods());
        assertEquals(registeredClient.getClientType(), updatedClient.getClientType());
        assertEquals(registeredClient.getRedirectUris(), updatedClient.getRedirectUris());
        assertEquals(registeredClient.getScopes(), updatedClient.getScopes());
        assertEquals(registeredClient.getContacts(), updatedClient.getContacts());
        assertEquals(registeredClient.getAdditionalInformation(), updatedClient.getAdditionalInformation());

    }

    @Test
    public void testUpdateRegisteredClientWhenUpdateAttributes() throws Exception{
        String newClient = "client1";
        String newSecret = "secret1";
        Set<String> scope = Set.of("email:read");
        String contact = "examples123@mail.com";
        String redirectUri = "https://www.example123.com";

        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClientTest.getRegisteredClient().build();
        OAuth2RegisteredClient updatedClient = OAuth2RegisteredClient.from(registeredClient)
                .clientID(newClient)
                .secret(newSecret)
                .scopes(s->{
                    s.clear();
                    s.addAll(scope);
                })
                .contacts(c ->{
                    c.clear();
                    c.add(contact);
                })
                .redirectUris(r -> {
                    r.clear();
                    r.add(redirectUri);
                }).build();

        assertEquals(newClient, updatedClient.getClientId().getValue());
        assertEquals(newSecret, updatedClient.getClientSecret().getValue());
        assertEquals(scope, updatedClient.getScopes());
        assertEquals(Set.of(redirectUri), updatedClient.getRedirectUris());
        assertEquals(Set.of(contact), updatedClient.getContacts());
    }

    public static OAuth2RegisteredClient.Builder getRegisteredClient(){
        Instant clientIDIssuedAt = Instant.now();
        Instant clientSecretExpiredAt = clientIDIssuedAt.plus(5,ChronoUnit.MINUTES);
        return OAuth2RegisteredClient.builder()
                .clientID(new ClientID("client"))
                .secret(new Secret("secret"))
                .clientIDIssuedAt(clientIDIssuedAt)
                .clientSecretExpiredAt(clientSecretExpiredAt)
                .redirectUris(r ->  r.addAll(REDIRECT_URIS))
                .scopes(s -> s.addAll(SCOPES))
                .clientType(ClientType.CONFIDENTIAL)
                .contacts(contact -> contact.add("exampleId@example.com"))
                .additionalInformations(information ->  information.put("key1", "value1"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.getDefault())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    public static OAuth2RegisteredClient.Builder getRegisteredClient2(){
        Instant clientIDIssuedAt = Instant.now();
        Instant clientSecretExpiredAt = clientIDIssuedAt.plus(5,ChronoUnit.MINUTES);
        return OAuth2RegisteredClient.builder()
                .clientID("client")
                .secret("secret")
                .clientIDIssuedAt(clientIDIssuedAt)
                .clientSecretExpiredAt(clientSecretExpiredAt)
                .redirectUri("https://www.example.com")
                .scope("profile:read")
                .clientType(ClientType.CONFIDENTIAL)
                .contact("exampleId@example.com")
                .additionalInformation("key1", "value1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.getDefault())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
    }
}
