package org.commerxo.core.oauth2;

import org.commerxo.core.oauth2.id.Identifier;

public final class ClientAuthenticationMethod extends Identifier {

    public static final ClientAuthenticationMethod CLIENT_SECRET_BASIC =
            new ClientAuthenticationMethod("client_secret_basic");

    public static final ClientAuthenticationMethod CLIENT_SECRET_POST =
            new ClientAuthenticationMethod("client_secret_post");

    public static final ClientAuthenticationMethod CLIENT_SECRET_JWT =
            new ClientAuthenticationMethod("client_secret_jwt");

    public static final ClientAuthenticationMethod PRIVATE_KEY_JWT =
            new ClientAuthenticationMethod("private_key_jwt");

    public static final ClientAuthenticationMethod NONE =
            new ClientAuthenticationMethod("none");


    public ClientAuthenticationMethod(final String value){
        super(value);
    }

    public static ClientAuthenticationMethod getDefault(){
        return CLIENT_SECRET_BASIC;
    }

    public static ClientAuthenticationMethod parse(final String value){
        if(value.equals(CLIENT_SECRET_BASIC.getValue())){
            return CLIENT_SECRET_BASIC;
        } else if (value.equals(CLIENT_SECRET_POST.getValue())) {
            return CLIENT_SECRET_POST;
        } else if (value.equals(CLIENT_SECRET_JWT.getValue())) {
            return CLIENT_SECRET_JWT;
        } else if (value.equals(PRIVATE_KEY_JWT.getValue())) {
            return PRIVATE_KEY_JWT;
        } else if (value.equals(NONE.getValue())) {
            return NONE;
        } else {
            return new ClientAuthenticationMethod(value);
        }
    }


}
