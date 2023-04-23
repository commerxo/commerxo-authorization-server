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
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Date;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class OAuth2ClientMetadataTest {

    private static final String JWKS_URI = "https://example.com/abc.json";
    private static final String POLICY_URI = "https://example.com/policy";
    private static final String TOS_URI = "https://example.com/tos";
    private static final String LOGO_URI = "https://example.com/logo";
    private static final String CLIENT_URI = "https://example.com/client";



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

    public static OAuth2ClientMetadata.Builder getClientMetadataWithSignedJwt() throws JOSEException, ParseException {
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
        return OAuth2ClientMetadata.builder()
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
                .contact("example@mail.com")
                .contacts(c->c.add("example1@mail.com"))
                .clientType(ClientType.CONFIDENTIAL)
                .redirectUri("https://www.example.com")
                .redirectUris(r->r.add("https://www.example1.com"));
    }
}
