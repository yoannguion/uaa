package org.cloudfoundry.identity.uaa.oauth.jwk;

@Deprecated
public interface JsonWebKeyElements {
    String getId();
    String getAlgorithm();
    String getKey();
    String getType();
    String getModulus();
    String getExponent();
    JsonWebKey.KeyUse getUse();
    String getKid();
    String getValue();
}

