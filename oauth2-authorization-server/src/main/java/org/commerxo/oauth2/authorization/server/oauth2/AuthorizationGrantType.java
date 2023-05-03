package org.commerxo.oauth2.authorization.server.oauth2;

import java.util.HashMap;
import java.util.Map;

/**
 Authorization Grant Type
 RFC 6749 - OAuth 2.0 Protocol Standard @see <a href = "https://datatracker.ietf.org/doc/html/rfc6749#section-1.3"> Section 1.3 </a>
 */
public enum AuthorizationGrantType {

    AUTHORIZATION_CODE("authorization_code"),
    CLIENT_CREDENTIAL("client_credential"),
    REFRESH_TOKEN("refresh_token"),
    PASSWORD("password"),
    IMPLICIT("implicit");

    private final String value;

    private static final Map<String, AuthorizationGrantType> lookup = new HashMap<>();

    static {
        for(AuthorizationGrantType authorizationGrant: AuthorizationGrantType.values()){
            lookup.put(authorizationGrant.getValue(), authorizationGrant);
        }
    }

    AuthorizationGrantType(String value){
        this.value = value;
    }

    public String getValue(){
        return this.value;
    }

    public static AuthorizationGrantType getByValue(String value){
        return lookup.get(value);
    }

}
