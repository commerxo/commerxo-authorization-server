package org.commerxo.oauth2.authorization.server.oauth2.id;



import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;

public class Identifier implements Serializable, Comparable<Identifier> {

    public static final int DEFAULT_BYTE_LENGTH = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    public Identifier(final String value){
        if (value == null){
            throw new IllegalArgumentException("The identifier value must not be null!");
        }
        if(value.isBlank()){
            throw new IllegalArgumentException("The identifier value must not be empty!");
        }
        this.value = value;
    }

    public Identifier(final int length){
        if(length < 1){
            throw new IllegalArgumentException("The byte length must be a positive number");
        }
        byte[] n = new byte[length];
        SECURE_RANDOM.nextBytes(n);
        this.value = Base64.getUrlEncoder().encodeToString(n);
    }

    public Identifier(){
        this(DEFAULT_BYTE_LENGTH);
    }

    public String getValue(){
        return this.value;
    }

    @Override
    public int compareTo(final Identifier o) {
        return getValue().compareTo(o.getValue());
    }

    @Override
    public String toString() {
        return "Identifier{" +
                "value='" + value + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Identifier that = (Identifier) o;

        return getValue() != null ? getValue().equals(that.getValue()) : that.getValue() == null;
    }

    @Override
    public int hashCode() {
        return getValue() != null ? getValue().hashCode() : 0;
    }


}
