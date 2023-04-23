package org.commerxo.core.oauth2.id;

import java.util.UUID;

public final class SoftwareID extends Identifier{

    public SoftwareID(String softwareId){
        super(softwareId);
    }

    public SoftwareID(){
        this(UUID.randomUUID().toString());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SoftwareID &&
                this.toString().equals(o.toString());
    }
}
