package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

public class IdentityProviderUtils {
    public static IdentityProvider getIdentityProviderByOriginKey(String adminToken,
                                                                  String uaaUrl,
                                                                  String zoneSubdomain,
                                                                  String originKey) {

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        ResponseEntity<IdentityProvider[]> response =
            restTemplate.exchange(uaaUrl + "/identity-providers", HttpMethod.GET, request, IdentityProvider[].class);

        IdentityProvider[] providers = response.getBody();
        for (IdentityProvider provider : providers) {
            if (provider.getOriginKey().equalsIgnoreCase(originKey)) {
                return provider;
            }
        }
        return null;
    }

    public static Optional<SamlServiceProvider> getServiceProviderByName(String adminToken,
                                                                         String uaaUrl,
                                                                         String zoneSubdomain,
                                                                         String spName) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        try {
            ResponseEntity<SamlServiceProvider[]> response =
                restTemplate.exchange(
                    uaaUrl + "/saml/service-providers", HttpMethod.GET, request, SamlServiceProvider[].class
                );

            SamlServiceProvider[] providers = response.getBody();
            for (SamlServiceProvider provider : providers) {
                if (provider.getName().equalsIgnoreCase(spName)) {
                    return Optional.of(provider);
                }
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                // ok to "fail" to delete entities that don't exist
            } else {
                throw e;
            }
        }
        return Optional.empty();
    }

    public static void deleteServiceProviderById(String adminToken, String uaaUrl, String zoneSubdomain, String spId) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        restTemplate.exchange(uaaUrl + "/saml/service-providers/{id}", HttpMethod.DELETE, request, String.class, spId);
    }

    public static void deleteServiceProviderByNameIfExists(String adminToken, String uaaUrl, String zoneSubdomain, String spName) {
        getServiceProviderByName(adminToken, uaaUrl, zoneSubdomain, spName).ifPresent(provider -> {
            deleteServiceProviderById(adminToken, uaaUrl, zoneSubdomain, provider.getId());
        });
    }
}
