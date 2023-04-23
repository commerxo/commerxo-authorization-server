package org.commerxo.core.oauth2;

import org.commerxo.core.oauth2.id.Identifier;

public final class OAuth2AuthorizationResponseType extends Identifier {

    public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");

    public static final OAuth2AuthorizationResponseType TOKEN = new OAuth2AuthorizationResponseType("token");

    private String value;

    public OAuth2AuthorizationResponseType(final String value){
        super(value);
    }

    public static OAuth2AuthorizationResponseType parse(String value){
        if(CODE.getValue().equals(value)){
            return CODE;
        } else if (TOKEN.getValue().equals(value)) {
            return TOKEN;
        }
        else {
            return new OAuth2AuthorizationResponseType(value);
        }
    }
}
