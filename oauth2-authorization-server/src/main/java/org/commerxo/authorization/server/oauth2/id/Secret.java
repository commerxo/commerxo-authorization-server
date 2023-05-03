package org.commerxo.authorization.server.oauth2.id;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public final class Secret implements Serializable {

    public static final int DEFAULT_BYTE_LENGTH = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private byte[] value;

    public Secret(){
        this(DEFAULT_BYTE_LENGTH);
    }

    public Secret(final String value){
        if(value == null){
            throw new IllegalArgumentException("Secret must not be null!");
        }
        if (value.isBlank()){
            throw new IllegalArgumentException("Secret must not be Blank or Empty!");
        }
        this.value = value.getBytes(StandardCharsets.UTF_8);
    }

    public Secret(final int byteLength){
        if(byteLength < 1){
            throw new IllegalArgumentException("");
        }
        byte[] n = new byte[byteLength];
        SECURE_RANDOM.nextBytes(n);
        this.value = Base64.getUrlEncoder().encodeToString(n).getBytes(StandardCharsets.UTF_8);
    }

    public String getValue(){
        if(this.value == null){
            return null;
        }
        return new String(this.value, StandardCharsets.UTF_8);
    }

    public byte[] getByteValue(){
        return this.value;
    }

    public void erase(){
        if(this.value == null){
            return; // already erased
        }
        Arrays.fill(this.value, (byte)'0');
        this.value = null;
    }

}
