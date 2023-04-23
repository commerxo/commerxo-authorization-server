package org.commerxo.core.oauth2.id;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ClientIDTest {

    @Test
    public void testDefaultLengthClientID() throws Exception{
        ClientID clientID = new ClientID();
        Assertions.assertNotNull(clientID);
        Assertions.assertNotNull(clientID.getValue());
    }
}
