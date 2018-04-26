package org.cloudfoundry.identity.uaa.integration.util;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.ExternalGroupMappingMode;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class SamlIntegrationTestUtils {
    private static final String IDP_METADATA_PATH = "/saml/idp/metadata";
    private static final String SP_METADATA_PATH = "/saml/metadata";
    private static final String SAML_SERVICE_PROVIDERS_PATH = "/saml/service-providers";

    private static final String SAML_NAME_ID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    private static final String ADMIN_CLIENT = "admin";
    private static final String ADMIN_CLIENT_SECRET = "adminsecret";

    public static String getIdpMetadata(String uaaUrl, String zoneSubdomain) {
        return getMetadata(uaaUrl, IDP_METADATA_PATH, zoneSubdomain);
    }

    public static String getSpMetadata(String uaaUrl, String zoneSubdomain) {
        return getMetadata(uaaUrl, SP_METADATA_PATH, zoneSubdomain);
    }

    public static IdentityProvider<SamlIdentityProviderDefinition> createUaaSamlIdentityProvider(String idpName,
                                                                                                 String uaaUrl,
                                                                                                 String metadataZone,
                                                                                                 String zoneSubdomain) {

        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setAddShadowUserOnLogin(true);
        definition.setStoreCustomAttributes(true);
        definition.setMetaDataLocation(
            SamlIntegrationTestUtils.getIdpMetadata(uaaUrl, metadataZone));
        definition.setNameID(SAML_NAME_ID);
        definition.setAssertionConsumerIndex(0);
        definition.setMetadataTrustCheck(false);
        definition.setShowSamlLink(true);
        definition.setLinkText("Login with UAA SAML");
        definition.setGroupMappingMode(
            ExternalGroupMappingMode.EXPLICITLY_MAPPED);
        definition.setSkipSslValidation(false);

        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setConfig(definition);
        identityProvider.setOriginKey(idpName);
        identityProvider.setName(idpName);
        identityProvider.setActive(true);
        identityProvider.setIdentityZoneId(zoneSubdomain);

        String adminClientToken = IntegrationTestUtils.getClientCredentialsToken(uaaUrl, ADMIN_CLIENT, ADMIN_CLIENT_SECRET);
        return IntegrationTestUtils.createOrUpdateProvider(adminClientToken, uaaUrl, identityProvider);
    }

    public static SamlServiceProvider createServiceProvider(String adminToken,
                                                            String uaaUrl,
                                                            String entityId,
                                                            String metadataZone,
                                                            String zoneSubdomain) {

        MultiValueMap<String, String> headers = createHeadersWithToken(adminToken, zoneSubdomain);

        SamlServiceProvider serviceProvider = generateServiceProviderConfig(metadataZone, entityId);
        serviceProvider.getConfig().setMetaDataLocation(getSpMetadata(uaaUrl, metadataZone));
        HttpEntity request = new HttpEntity<>(serviceProvider, headers);

        ResponseEntity<SamlServiceProvider> responseEntity =
            new RestTemplate().exchange(uaaUrl + SAML_SERVICE_PROVIDERS_PATH, HttpMethod.POST, request, SamlServiceProvider.class);

        return responseEntity.getBody();
    }

    private static String getMetadata(String uaaUrl,
                                      String metadataPath,
                                      String zoneSubdomain) {

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(uaaUrl, new String[0], "admin", "adminsecret"));

        // TODO: support https URLs
        if (!StringUtils.isBlank(zoneSubdomain)) {
            uaaUrl = uaaUrl.replaceAll("https?://", "http://" + zoneSubdomain + ".");
        }

        ResponseEntity<String> responseEntity =
            adminClient.getForEntity(uaaUrl + metadataPath, String.class);

        return responseEntity.getBody();
    }

    private static MultiValueMap<String, String> createHeadersWithToken(String token, String zoneSubdomain) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (!StringUtils.isBlank(zoneSubdomain)) {
            headers.add("X-Identity-Zone-Subdomain", zoneSubdomain);
        }
        return headers;
    }

    private static SamlServiceProvider generateServiceProviderConfig(String name, String entityId) {
        SamlServiceProvider config = new SamlServiceProvider();
        config.setName(name);
        config.setConfig(new SamlServiceProviderDefinition());
        return config;
    }
}
