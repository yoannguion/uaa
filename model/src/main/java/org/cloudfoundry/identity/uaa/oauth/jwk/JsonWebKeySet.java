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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.*;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeySet {

    private final List<JsonWebKey> keys;

    public JsonWebKeySet(@JsonProperty("keys") List<JsonWebKey> keys) {
        Set<JsonWebKey> set = new LinkedHashSet<>();
        //rules for how to override duplicates
        for (JsonWebKey key : keys) {
            if(key == null) continue;
            set.remove(key);
            set.add(key);
        }
        this.keys = new ArrayList<>(set);
    }

    public List<JsonWebKey> getKeys() {
        return Collections.unmodifiableList(keys);
    }
}
