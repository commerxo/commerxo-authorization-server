package org.commerxo.core.oauth2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RoleTest {

    @Test
    public void testRoles(){
        Assertions.assertEquals("authorization_server", Roles.AUTHORIZATION_SERVER.getValue());
        Assertions.assertEquals(Roles.CLIENT, Roles.getByValue("client"));
    }
}
