package org.commerxo.authorization.server.oauth2.id;

/**
 RFC 6749 - OAuth 2.0 Protocol Standard @see <a href = "https://datatracker.ietf.org/doc/html/rfc6749#section-2.2"> Section 2.2 </a>
 */
public final class ClientID extends Identifier {

    /**
     * Create a new Client ID by specifying a value
     * @param value Client identifier value must not be {@code null} or empty String
     */
    public ClientID(final String value) {
        super(value);
    }

    /**
     * Create a new client with randomly generated value of specified byte length, using Base64-URL Encoder
     * @param length The length used to generate a value. Must be positive length
     */
    public ClientID(final int length) {
        super(length);
    }

    /**
     * Create a new Client ID by specifying a value
     * @param identifier Client identifier value must not be {@code null}
     */
    public ClientID(final Identifier identifier){
        super(identifier.getValue());
    }

    /**
     * Generate client identifier with default 32 byte length
     */
    public ClientID() {
        super();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ClientID &&
                this.toString().equals(o.toString());
    }

}
