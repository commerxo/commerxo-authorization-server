package org.commerxo.core.oauth2.id;

public final class SoftwareVersion extends Identifier{

    public SoftwareVersion(String version){
        super(version);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SoftwareVersion &&
                this.toString().equals(o.toString());
    }
}
