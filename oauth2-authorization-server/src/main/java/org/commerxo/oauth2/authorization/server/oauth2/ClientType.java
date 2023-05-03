package org.commerxo.oauth2.authorization.server.oauth2;

import java.util.HashMap;
import java.util.Map;

/**
 RFC 6749 - OAuth 2.0 Protocol Standard @see <a href = "https://datatracker.ietf.org/doc/html/rfc6749#section-2.1"> Section 2.1 </a>
 */
public enum ClientType {

    /**
     Clients capable of maintaining the confidentiality of their
     credentials (e.g., client implemented on a secure server with
     restricted access to the client credentials), or capable of secure
     client authentication using other means.
     */
    CONFIDENTIAL("confidential"),

    /**
     Clients incapable of maintaining the confidentiality of their
     credentials (e.g., clients executing on the device used by the
     resource owner, such as an installed native application or a web
     browser-based application), and incapable of secure client
     authentication via any other means.
     */
    PUBLIC("public");

    private final String value;

    private static final Map<String, ClientType> lookup = new HashMap<>();

    static {
        for(ClientType clientType: ClientType.values()){
            lookup.put(clientType.getValue(), clientType);
        }
    }

    ClientType(String value){
        this.value = value;
    }

    public String getValue(){
        return this.value;
    }

    public static ClientType getByValue(String value){
        return lookup.get(value);
    }

}
