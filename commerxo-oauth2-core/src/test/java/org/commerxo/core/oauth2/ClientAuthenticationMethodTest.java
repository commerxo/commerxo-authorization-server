package org.commerxo.core.oauth2;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ClientAuthenticationMethodTest {

    @Test
    public void testConstants() throws Exception{
        assertEquals("client_secret_basic", ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        assertEquals("client_secret_post", ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
        assertEquals("client_secret_jwt", ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
        assertEquals("private_key_jwt", ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
        assertEquals("none", ClientAuthenticationMethod.NONE.getValue());
    }

    @Test
    public void testDefaultClientAuthenticationMethod() throws Exception{
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.getDefault());
    }

    @Test
    public void testParse() throws Exception{
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.parse("client_secret_basic"));
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.parse("client_secret_post"));
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, ClientAuthenticationMethod.parse("client_secret_jwt"));
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.parse("private_key_jwt"));
        assertEquals(ClientAuthenticationMethod.NONE, ClientAuthenticationMethod.parse("none"));
    }

    @Test
    public void testParseWithNull() throws Exception{
        try {
            ClientAuthenticationMethod.parse("");
            fail();
        }
        catch (IllegalArgumentException ignored){}
    }
}
