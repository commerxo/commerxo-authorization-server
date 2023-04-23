package org.commerxo.core.oauth2.client;

import org.commerxo.core.oauth2.id.ClientID;
import org.commerxo.core.oauth2.id.Secret;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

public class OAuth2ClientInformationTest {

    @Test
    public void testClientInformationWhenClientIDIsNull() throws Exception{
        assertThrows(IllegalArgumentException.class, () -> OAuth2ClientInformation.builder()
                .clientID((String)null)
                .secret("secret").build());
    }

    @Test
    public void testClientInformationWhenClientSecretIsNull() throws Exception{
        assertThrows(IllegalArgumentException.class, () -> OAuth2ClientInformation.builder()
                .clientID("client")
                .secret((String)null).build());
    }

    @Test
    public void testClientInformationWhenClientIDIsEmpty() throws Exception{
        assertThrows(IllegalArgumentException.class, () -> OAuth2ClientInformation.builder()
                .clientID("")
                .secret("secret").build());
    }

    @Test
    public void testClientInformationWhenClientSecretIsEmpty() throws Exception{
        assertThrows(IllegalArgumentException.class, () -> OAuth2ClientInformation.builder()
                .clientID("client")
                .secret("").build());
    }

    @Test
    public void testClientInformationWhenClientNameNotPresent() throws Exception{
        Instant clientIDIssuedAt = Instant.now();
        Instant clientSecretExpiredAt = clientIDIssuedAt.plus(5, ChronoUnit.DAYS);
        OAuth2ClientInformation clientInformation = OAuth2ClientInformation.builder()
                .clientID("client")
                .secret("secret")
                .clientIDIssuedAt(clientIDIssuedAt)
                .clientSecretExpiredAt(clientSecretExpiredAt)
                .clientRegisteredUri("https://example.com/client")
                .clientMetadata(OAuth2ClientMetadataTest.getClientMetadata().build())
                .build();

        assertEquals("client", clientInformation.getClientId().getValue());
        assertEquals("secret", clientInformation.getSecret().getValue());
        assertEquals("client", clientInformation.getClientName());
        assertEquals(clientIDIssuedAt, clientInformation.getClientIDIssuedAt());
        assertEquals(clientSecretExpiredAt, clientInformation.getClientSecretExpiredAt());
        assertEquals("https://example.com/client", clientInformation.getClientRegisteredUri());
        assertNotNull(clientInformation.getClientMetadata());
    }

    @Test
    public void testClientInformationAllAttributes() throws Exception{
        OAuth2ClientInformation clientInformation = OAuth2ClientInformationTest.getClientInformation().build();
        assertEquals("client", clientInformation.getClientId().getValue());
        assertEquals("secret", clientInformation.getSecret().getValue());
        assertEquals("client_name", clientInformation.getClientName());
        assertEquals("https://example.com/client", clientInformation.getClientRegisteredUri());
        assertNotNull(clientInformation.getClientMetadata());
    }

    @Test
    public void testClientInformationWhenMakeCopy() {
        OAuth2ClientInformation clientInformation = OAuth2ClientInformationTest.getClientInformation().build();
        OAuth2ClientInformation updatedClientInformation = OAuth2ClientInformation.from(clientInformation).build();

        assertEquals(clientInformation.getClientId().getValue(), updatedClientInformation.getClientId().getValue());
        assertEquals(clientInformation.getSecret().getValue(), updatedClientInformation.getSecret().getValue());
        assertEquals(clientInformation.getClientName(), updatedClientInformation.getClientName());
        assertEquals(clientInformation.getClientIDIssuedAt(), updatedClientInformation.getClientIDIssuedAt());
        assertEquals(clientInformation.getClientSecretExpiredAt(), updatedClientInformation.getClientSecretExpiredAt());
        assertEquals(clientInformation.getClientRegisteredUri(), updatedClientInformation.getClientRegisteredUri());
        assertEquals(clientInformation.getClientMetadata().getJwksUri(), updatedClientInformation.getClientMetadata().getJwksUri());
        assertEquals(clientInformation.getClientMetadata().getRedirectUris(), updatedClientInformation.getClientMetadata().getRedirectUris());
    }

    @Test
    public void testClientInformationWhenUpdateAttributes() {
        String newClientID = "client1";
        String newClientSecret = "secret1";
        String newName = "client_name1";
        String registeredUri = "https://example.com/client1";
        OAuth2ClientInformation clientInformation = OAuth2ClientInformationTest.getClientInformation().build();
        OAuth2ClientInformation updatedClientInformation = OAuth2ClientInformation.from(clientInformation)
                .clientID(new ClientID(newClientID))
                .secret(new Secret(newClientSecret))
                .clientName(newName)
                .clientRegisteredUri(registeredUri)
                .build();
        assertEquals(newClientID, updatedClientInformation.getClientId().getValue());
        assertEquals(newClientSecret, updatedClientInformation.getSecret().getValue());
        assertEquals(newName, updatedClientInformation.getClientName());
        assertEquals(registeredUri, updatedClientInformation.getClientRegisteredUri());
        assertNotNull(updatedClientInformation.getClientMetadata());
    }

    public static OAuth2ClientInformation.Builder getClientInformation(){
        Instant clientIDIssuedAt = Instant.now();
        Instant clientSecretExpiredAt = clientIDIssuedAt.plus(5, ChronoUnit.DAYS);
        return OAuth2ClientInformation.builder()
                .clientID("client")
                .secret("secret")
                .clientIDIssuedAt(clientIDIssuedAt)
                .clientSecretExpiredAt(clientSecretExpiredAt)
                .clientName("client_name")
                .clientRegisteredUri("https://example.com/client")
                .clientMetadata(OAuth2ClientMetadataTest.getClientMetadata().build());
    }
}
