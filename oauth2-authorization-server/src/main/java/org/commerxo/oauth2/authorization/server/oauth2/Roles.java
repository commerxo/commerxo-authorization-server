package org.commerxo.oauth2.authorization.server.oauth2;

import java.util.HashMap;
import java.util.Map;

/**
 * RFC 6749 - OAuth 2.0 Protocol Standard @see <a href = "https://datatracker.ietf.org/doc/html/rfc6749#section-1.1"> Section 1.1</a>
 */
public enum Roles {

    /**
      An application making protected resource requests on behalf of the
      resource owner and with its authorization.  The term "client" does
      not imply any particular implementation characteristics (e.g.,
      whether the application executes on a server, a desktop, or other
      devices).
     */
    CLIENT("client"),

    /**
       An entity capable of granting access to a protected resource.
       When the resource owner is a person, it is referred to as an
       end-user.
     */
    RESOURCE_OWNER("resource_server"),

    /**
     The server hosting the protected resources, capable of accepting
     and responding to protected resource requests using access tokens.
     */
    RESOURCE_SERVER("resource_owner"),

    /**
     The server issuing access tokens to the client after successfully
     authenticating the resource owner and obtaining authorization
     */
    AUTHORIZATION_SERVER("authorization_server");

    private final String value;

    private static final Map<String, Roles> lookUp = new HashMap<>();

    static {
        for(Roles roles: Roles.values()){
            lookUp.put(roles.getValue(), roles);
        }
    }

    Roles(String value){
        this.value = value;
    }

    public String getValue(){
        return this.value;
    }

    public static Roles getByValue(String value){
        return lookUp.get(value);
    }

}
