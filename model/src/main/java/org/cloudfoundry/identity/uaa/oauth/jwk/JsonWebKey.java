/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.springframework.util.StringUtils.hasText;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
@JsonDeserialize(using = JsonWebKeyDeserializer.class)
@JsonSerialize(using = JsonWebKeySerializer.class)
public class JsonWebKey {

    public enum KeyUse {
        sig,
        enc
    }

    public enum KeyType {
        RSA,
        MAC
    }

    public enum KeyOperation {
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits
    }

    public static String KID = "kid";
    private static String KTY = "kty";
    public static String ALG = "alg";

    private final Map<String, Object> json;

    public JsonWebKey(Map<String, Object> json) {
        if (json.get("kty") == null) {
            throw new IllegalArgumentException("kty field is required");
        }
        KeyType.valueOf((String) json.get("kty"));
        this.json = new HashMap<>(json);
    }

    Map<String, Object> getKeyProperties() {
        return Collections.unmodifiableMap(json);
    }

    private String getStringProperty(String property) {
        return (String) getKeyProperties().get(property);
    }

    public final KeyType getKty() {
        return KeyType.valueOf(getStringProperty(KTY));
    }

    public final String getKid() {
        return getStringProperty(KID);
    }

    public JsonWebKey setKid(String kid) {
        this.json.put(KID, kid);
        return this;
    }

    public final KeyUse getUse() {
        String use = getStringProperty("use");
        if (hasText(use)) {
            return KeyUse.valueOf(use);
        }
        return null;
    }

    public String getId() {
        return getKid();
    }

    public String getKey() {
        return getStringProperty("value");
    }

    public String getType() {
        return getKty().name();
    }

    public String getModulus() {
        return getStringProperty("n");
    }

    public String getExponent() {
        return getStringProperty("e");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JsonWebKey)) return false;
        JsonWebKey that = (JsonWebKey) o;
        return getKid() != null ? getKid().equals(that.getKid()) : that.getKid() == null && getKeyProperties().equals(that.getKeyProperties());
    }

    @Override
    public int hashCode() {
        if (getKid() == null) {
            return getKty().hashCode();
        } else {
            return getKid().hashCode();
        }
    }

    public String getAlgorithm() {
        return getStringProperty(ALG);
    }

    public String getValue() {
        String result = getStringProperty("value");
        if(result != null) {
            return result;
        }

        if (RSA.equals(getKty())) {
            result = pemEncodePublicKey(getRsaPublicKey());
            this.json.put("value", result);
        } else if (MAC.equals(getKty())) {
            result = getStringProperty("k");
            this.json.put("value", result);
        }
        return result;
    }

    Set<KeyOperation> getKeyOps() {
        Object key_ops = getKeyProperties().get("key_ops");

        List<Object> key_ops_list = key_ops instanceof List ? (List) key_ops : null;

        if (key_ops_list == null) {
            return Collections.emptySet();
        }

        return key_ops_list.stream()
                .map(String::valueOf)
                .map(KeyOperation::valueOf)
                .collect(Collectors.toSet());
    }

    private static String pemEncodePublicKey(PublicKey publicKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = publicKey.getEncoded();
        String base64encoded = new String(new Base64(false).encode(data));
        return begin + base64encoded + end;
    }

    PublicKey getRsaPublicKey() {
        final Base64 decoder = new Base64(true);
        BigInteger modulus = new BigInteger(1, decoder.decode(getModulus().getBytes(StandardCharsets.UTF_8)));
        BigInteger exponent = new BigInteger(1, decoder.decode(getExponent().getBytes(StandardCharsets.UTF_8)));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(modulus, exponent)
            );
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
