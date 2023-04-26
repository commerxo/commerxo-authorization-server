package org.commerxo.core.oauth2.request;

import org.commerxo.core.oauth2.AuthorizationGrantType;
import org.commerxo.core.oauth2.OAuth2AuthorizationResponseType;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OAuth2AuthorizationRequestTest {

    public static final String STATE = "1ejhde";
    public static final String CLIENT_ID = "client";
    public static final String AUTHORIZATION_REQUEST_URI = "https://www.example.com/oauth2/authorize?clientId=client&scope=profile:read&response_type=code";
    public static final String AUTHORIZATION_URI = "https://www.example.com";
    public static final String REDIRECT_URI = "https://example.com/callback";
    public static final Set<String> SCOPES = Set.of("profile:read", "email:read");
    public static final Map<String, Object> ADDITIONAL_ATTRIBUTE = Map.of("key1", "value1");


    @Test
    public void testAuthorizationRequestWhenAuthorizationUriIsEmpty() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> OAuth2AuthorizationRequest.authorizationCode()
                .authorizationRequestUri(AUTHORIZATION_REQUEST_URI)
                .clientID("client")
                .build());
    }

    @Test
    public void testAuthorizationRequestWhenClientIDIsEmpty() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> OAuth2AuthorizationRequest.authorizationCode()
                .authorizationRequestUri(AUTHORIZATION_REQUEST_URI)
                .authorizationUri("https://www.example.com/oauth2/authorize")
                .build());
    }

    @Test
    public void testAuthorizationRequestWhenGrantTypeIsNull() throws Exception {
       assertThrows(IllegalArgumentException.class, () ->
               new OAuth2AuthorizationRequest.Builder((AuthorizationGrantType) null).build());
    }


    @Test
    public void testAuthorizationRequestAllAttributes() throws Exception {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequestTest
                .getAuthorizationRequest()
                .build();
        assertEquals(CLIENT_ID, authorizationRequest.getClientId());
        assertEquals(AUTHORIZATION_REQUEST_URI, authorizationRequest.getAuthorizationRequestUri());
        assertEquals(AUTHORIZATION_URI, authorizationRequest.getAuthorizationUri());
        assertEquals(SCOPES, authorizationRequest.getScopes());
        assertEquals(REDIRECT_URI, authorizationRequest.getRedirectUri());
        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, authorizationRequest.getAuthorizationGrantType());
        assertEquals(OAuth2AuthorizationResponseType.CODE, authorizationRequest.getAuthorizationResponseType());
        assertEquals(STATE, authorizationRequest.getState());
        assertEquals(ADDITIONAL_ATTRIBUTE, authorizationRequest.getAdditionalParameters());
    }

    @Test
    public void testAuthorizationRequestWhenMakeCopyAllAttributes() throws Exception {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequestTest.getAuthorizationRequest().build();
        OAuth2AuthorizationRequest updatedAuthorizationRequest = OAuth2AuthorizationRequest.from(authorizationRequest).build();

        assertEquals(authorizationRequest.getClientId(), updatedAuthorizationRequest.getClientId());
        assertEquals(authorizationRequest.getScopes(), updatedAuthorizationRequest.getScopes());
        assertEquals(authorizationRequest.getState(), updatedAuthorizationRequest.getState());
        assertEquals(authorizationRequest.getAuthorizationUri(), updatedAuthorizationRequest.getAuthorizationUri());
        assertEquals(authorizationRequest.getAuthorizationRequestUri(), updatedAuthorizationRequest.getAuthorizationRequestUri());
        assertEquals(authorizationRequest.getAuthorizationGrantType(), updatedAuthorizationRequest.getAuthorizationGrantType());
        assertEquals(authorizationRequest.getAuthorizationResponseType(), updatedAuthorizationRequest.getAuthorizationResponseType());
        assertEquals(authorizationRequest.getRedirectUri(), updatedAuthorizationRequest.getRedirectUri());
        assertEquals(authorizationRequest.getAdditionalParameters(), updatedAuthorizationRequest.getAdditionalParameters());
    }

    @Test
    public void testAuthorizationRequestWhenUpdateAttributes() throws Exception {
        final String NEW_STATE = "1ejh3e";
        final String NEW_CLIENT_ID = "client1";
        final String NEW_AUTHORIZATION_REQUEST_URI = "https://www.example2.com/oauth2/authorize?clientId=client&scope=profile:read&response_type=code";
        final String NEW_AUTHORIZATION_URI = "https://www.example2.com";
        final String NEW_REDIRECT_URI = "https://example2.com/callback";
        final Set<String> NEW_SCOPES = Set.of("profile:read1", "email:read1");
        final Map<String, Object> NEW_ADDITIONAL_ATTRIBUTE = Map.of("key11", "value11");
        
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequestTest.getAuthorizationRequest().build();
        OAuth2AuthorizationRequest updatedAuthorizationRequest = OAuth2AuthorizationRequest.from(authorizationRequest)
                .clientID(NEW_CLIENT_ID)
                .authorizationUri(NEW_AUTHORIZATION_URI)
                .authorizationRequestUri(NEW_AUTHORIZATION_REQUEST_URI)
                .scopes(s->{
                    s.clear();
                    s.addAll(NEW_SCOPES);
                })
                .state(NEW_STATE)
                .redirectUri(NEW_REDIRECT_URI)
                .additionalParameters(a ->{
                    a.clear();
                    a.putAll(NEW_ADDITIONAL_ATTRIBUTE);
                })
                .build();

        assertEquals(NEW_CLIENT_ID, updatedAuthorizationRequest.getClientId());
        assertEquals(NEW_SCOPES, updatedAuthorizationRequest.getScopes());
        assertEquals(NEW_STATE, updatedAuthorizationRequest.getState());
        assertEquals(NEW_AUTHORIZATION_URI, updatedAuthorizationRequest.getAuthorizationUri());
        assertEquals(NEW_AUTHORIZATION_REQUEST_URI, updatedAuthorizationRequest.getAuthorizationRequestUri());
        assertEquals(authorizationRequest.getAuthorizationGrantType(), updatedAuthorizationRequest.getAuthorizationGrantType());
        assertEquals(authorizationRequest.getAuthorizationResponseType(), updatedAuthorizationRequest.getAuthorizationResponseType());
        assertEquals(NEW_REDIRECT_URI, updatedAuthorizationRequest.getRedirectUri());;
        assertEquals(NEW_ADDITIONAL_ATTRIBUTE, updatedAuthorizationRequest.getAdditionalParameters());
    }

    private static OAuth2AuthorizationRequest.Builder getAuthorizationRequest() throws Exception {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(AUTHORIZATION_URI)
                .authorizationRequestUri(AUTHORIZATION_REQUEST_URI)
                .scopes(s -> s.addAll(SCOPES))
                .clientID(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationResponseType(OAuth2AuthorizationResponseType.CODE)
                .redirectUri(REDIRECT_URI)
                .state(STATE)
                .additionalParameters(a->a.putAll(ADDITIONAL_ATTRIBUTE));
    }
}
