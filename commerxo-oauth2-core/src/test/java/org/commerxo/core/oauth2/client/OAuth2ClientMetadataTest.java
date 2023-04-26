package org.commerxo.core.oauth2.client;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.ClientAuthenticationMethod;
import org.commerxo.core.oauth2.ClientType;
import org.commerxo.core.oauth2.id.SoftwareID;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class OAuth2ClientMetadataTest {

    private static final String JWKS_URI = "https://example.com/abc.json";
    private static final String POLICY_URI = "https://example.com/policy";
    private static final String TOS_URI = "https://example.com/tos";
    private static final String LOGO_URI = "https://example.com/logo";
    private static final String CLIENT_URI = "https://example.com/client";

    @Test
    public void testClientMetadataWhenRedirectUriNotProvidedAndGrantTypeAuthorizationCode() throws Exception{
        assertThrows(IllegalArgumentException.class, () ->{
           OAuth2ClientMetadata.builder()
                   .grantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                   .build();
        });
    }

    @Test
    public void testClientMetadata() throws Exception{
        OAuth2ClientMetadata clientMetadata = OAuth2ClientMetadataTest.getClientMetadata().build();

        assertEquals("abcd",((RSAKey)clientMetadata.getJwkSet().getKeys().get(0)).getModulus().toString());
        assertEquals("xyz",((RSAKey)clientMetadata.getJwkSet().getKeys().get(0)).getPublicExponent().toString());
        assertEquals(JWKS_URI, clientMetadata.getJwksUri());
        assertEquals("1245", clientMetadata.getSoftwareID().getValue());
        assertEquals("V1.0", clientMetadata.getSoftwareVersion().getValue());
        assertEquals(POLICY_URI, clientMetadata.getPolicyUri());
        assertEquals(LOGO_URI, clientMetadata.getLogoUri());
        assertEquals(CLIENT_URI, clientMetadata.getClientUri());
        assertEquals(ClientAuthenticationMethod.getDefault(), clientMetadata.getClientAuthenticationMethod());
        assertEquals(JWSAlgorithm.RS256, clientMetadata.getClientAuthenticationAlg());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIAL), clientMetadata.getGrantTypes());
        assertEquals(Set.of("profile:read", "email:read"), clientMetadata.getScopes());
        assertEquals(TOS_URI, clientMetadata.getTosUri());
        assertEquals(ClientType.CONFIDENTIAL, clientMetadata.getClientType());
        assertEquals(Set.of("example@mail.com", "example1@mail.com"), clientMetadata.getContacts());
        assertEquals(Set.of("https://www.example.com","https://www.example1.com"), clientMetadata.getRedirectUris());

    }

    @Test
    public void testClientMetadataWhenUpdateAttributes() throws Exception{
        String jwks_uri = "https://example.com/jwks/abc.json";
        String policy_uri = "https://example.com/policy";
        String softwareVersion = "V2.0";
        Set<String> redirectUris = Set.of("https://www.examples.com/callback");
        Set<String> contacts = Set.of("example@email.com");
        Set<String> scopes = Set.of("blog:read");
        Map<String, Object> additionalInformation = Map.of("key2", "value2", "key1", "value1");

        OAuth2ClientMetadata clientMetadata = OAuth2ClientMetadataTest.getClientMetadata().build();
        OAuth2ClientMetadata updatedClientMetadata = OAuth2ClientMetadata.from(clientMetadata)
                .jwksUri(jwks_uri)
                .policyUri(policy_uri)
                .redirectUris(r -> {
                    r.clear();
                    r.addAll(redirectUris);
                })
                .contacts(c -> {
                    c.clear();
                    c.addAll(contacts);
                })
                .scopes(s -> {
                    s.clear();
                    s.addAll(scopes);
                })
                .softwareID(new SoftwareID())
                .softwareVersion(softwareVersion)
                .additionalInformations(a -> a.putAll(additionalInformation))
                .build();

        assertEquals(scopes, updatedClientMetadata.getScopes());
        assertEquals(jwks_uri, updatedClientMetadata.getJwksUri());
        assertEquals(contacts, updatedClientMetadata.getContacts());
        assertEquals(policy_uri, updatedClientMetadata.getPolicyUri());
        assertNotNull(updatedClientMetadata.getSoftwareID().getValue());
        assertEquals(redirectUris, updatedClientMetadata.getRedirectUris());
        assertEquals(softwareVersion, updatedClientMetadata.getSoftwareVersion().getValue());
        assertEquals(additionalInformation, updatedClientMetadata.getAdditionalInformation());

    }

    @Test
    public void testClientMetadataWhenMakeCopy() throws Exception{
        OAuth2ClientMetadata clientMetadata = OAuth2ClientMetadataTest.getClientMetadata().build();
        OAuth2ClientMetadata updatedClientMetadata = OAuth2ClientMetadata.from(clientMetadata).build();

        assertEquals(clientMetadata.getJwksUri(), updatedClientMetadata.getJwksUri());
        assertEquals(((RSAKey)clientMetadata.getJwkSet().getKeys().get(0)).getModulus().toString(), ((RSAKey)updatedClientMetadata.getJwkSet().getKeys().get(0)).getModulus().toString());
        assertEquals(((RSAKey)clientMetadata.getJwkSet().getKeys().get(0)).getPublicExponent().toString(), ((RSAKey)updatedClientMetadata.getJwkSet().getKeys().get(0)).getPublicExponent().toString());
        assertEquals(clientMetadata.getSoftwareID().getValue(), updatedClientMetadata.getSoftwareID().getValue());
        assertEquals(clientMetadata.getSoftwareVersion().getValue(), updatedClientMetadata.getSoftwareVersion().getValue());
        assertEquals(clientMetadata.getPolicyUri(), updatedClientMetadata.getPolicyUri());
        assertEquals(clientMetadata.getLogoUri(), updatedClientMetadata.getLogoUri());
        assertEquals(clientMetadata.getClientUri(), updatedClientMetadata.getClientUri());
        assertEquals(clientMetadata.getClientAuthenticationMethod(), updatedClientMetadata.getClientAuthenticationMethod());
        assertEquals(clientMetadata.getClientAuthenticationAlg(), updatedClientMetadata.getClientAuthenticationAlg());
        assertEquals(clientMetadata.getGrantTypes(), updatedClientMetadata.getGrantTypes());
        assertEquals(clientMetadata.getScopes(), updatedClientMetadata.getScopes());
        assertEquals(clientMetadata.getTosUri(), updatedClientMetadata.getTosUri());
        assertEquals(clientMetadata.getClientType(), updatedClientMetadata.getClientType());
        assertEquals(clientMetadata.getContacts(), updatedClientMetadata.getContacts());
        assertEquals(clientMetadata.getRedirectUris(), updatedClientMetadata.getRedirectUris());
    }

    public static OAuth2ClientMetadata.Builder getClientMetadata(){
        RSAKey rsaKey = new RSAKey.Builder(new Base64URL("abcd"), new Base64URL("xyz")).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return OAuth2ClientMetadata.builder()
                .jwkSet(jwkSet)
                .jwksUri(JWKS_URI)
                .softwareID("1245")
                .softwareVersion("V1.0")
                .policyUri(POLICY_URI)
                .clientUri(CLIENT_URI)
                .logoUri(LOGO_URI)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationAlg(JWSAlgorithm.RS256)
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .grantTypes(g -> g.add(AuthorizationGrantType.CLIENT_CREDENTIAL))
                .scope("profile:read")
                .scopes(s->s.add("email:read"))
                .tosUri(TOS_URI)
                .contact("example@mail.com")
                .contacts(c->c.add("example1@mail.com"))
                .clientType(ClientType.CONFIDENTIAL)
                .redirectUri("https://www.example.com")
                .redirectUris(r->r.add("https://www.example1.com"));
    }

    @Test
    public void testClientMetadataWithSignedJwt() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("1234")
                .generate();
        RSAKey rsaPublicJWK = rsaKey.toPublicJWK();
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claimsSet);
        signedJWT.sign(signer);
        String s = signedJWT.serialize();

        signedJWT = SignedJWT.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);

        RSAKey rsaJwkSet = new RSAKey.Builder(new Base64URL("abcd"), new Base64URL("xyz")).build();
        JWKSet jwkSet = new JWKSet(rsaJwkSet);
        OAuth2ClientMetadata clientMetadata = OAuth2ClientMetadata.builder()
                .jwkSet(jwkSet)
                .jwksUri(JWKS_URI)
                .softwareID("1245")
                .softwareVersion("V1.0")
                .policyUri(POLICY_URI)
                .clientUri(CLIENT_URI)
                .logoUri(LOGO_URI)
                .softwareStatement(signedJWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationAlg(JWSAlgorithm.RS256)
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .grantTypes(g -> g.add(AuthorizationGrantType.CLIENT_CREDENTIAL))
                .scope("profile:read")
                .scopes(s1->s1.add("email:read"))
                .tosUri(TOS_URI)
                .additionalInformation("key1", "value2")
                .contact("example@mail.com")
                .contacts(c->c.add("example1@mail.com"))
                .clientType(ClientType.CONFIDENTIAL)
                .redirectUri("https://www.example.com")
                .redirectUris(r->r.add("https://www.example1.com")).build();

        assertTrue(signedJWT.verify(verifier));
        assertEquals("alice", clientMetadata.getSoftwareStatement().getJWTClaimsSet().getSubject());
        assertEquals("https://c2id.com", clientMetadata.getSoftwareStatement().getJWTClaimsSet().getIssuer());
        assertTrue(new Date().before(clientMetadata.getSoftwareStatement().getJWTClaimsSet().getExpirationTime()));

    }
}
