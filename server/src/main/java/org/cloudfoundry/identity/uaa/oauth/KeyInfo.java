package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtAlgorithms;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;

public abstract class KeyInfo {
    public abstract void verify();

    public abstract SignatureVerifier getVerifier();

    public abstract Signer getSigner();

    public abstract String keyId();

    public abstract String keyURL();

    public abstract String type();

    public abstract String verifierKey();

    public abstract Map<String, Object> getJwkMap();

    public abstract String algorithm();

    protected String validateAndConstructTokenKeyUrl(String keyUrl) {
        if (!UaaUrlUtils.isUrl(keyUrl)) {
            throw new IllegalArgumentException("Invalid Key URL");
        }

        return UriComponentsBuilder.fromHttpUrl(keyUrl).scheme("https").path("/token_keys").build().toUriString();
    }
}

class HmacKeyInfo extends KeyInfo {
    private Signer signer;
    private SignatureVerifier verifier;
    private final String keyId;
    private final String keyUrl;
    private final String verifierKey;

    public HmacKeyInfo(String keyId, String signingKey, String keyUrl) {
        this.keyUrl = validateAndConstructTokenKeyUrl(keyUrl);

        this.signer = new MacSigner(signingKey);
        this.verifier = new MacSigner(signingKey);

        this.keyId = keyId;
        this.verifierKey = signingKey;
    }

    @Override
    public void verify() {

    }

    @Override
    public SignatureVerifier getVerifier() {
        return this.verifier;
    }

    @Override
    public Signer getSigner() {
        return this.signer;
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public String keyURL() {
        return this.keyUrl;
    }

    @Override
    public String type() {
        return MAC.name();
    }

    @Override
    public String verifierKey() {
        return this.verifierKey;
    }

    @Override
    public Map<String, Object> getJwkMap() {
        Map<String, Object> result = new HashMap<>();
        result.put("alg", this.algorithm());
        result.put("value", this.verifierKey);
        //new values per OpenID and JWK spec
        result.put("use", JsonWebKey.KeyUse.sig.name());
        result.put("kid", this.keyId);
        result.put("kty", MAC.name());
        return result;
    }

    @Override
    public String algorithm() {
        return JwtAlgorithms.sigAlg(verifier.algorithm());
    }
}