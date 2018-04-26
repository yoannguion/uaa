package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.junit.Assert.assertTrue;

public class UaaSamlIdpCreator {
    private final String adminToken;
    private String uaaBaseUrl;
    private final String idpZone;
    private final String spZone;
    private IdentityProvider<SamlIdentityProviderDefinition> idpRegistration;

    public UaaSamlIdpCreator(String adminToken, String uaaBaseUrl, String idpZone, String spZone) {
        this.adminToken = adminToken;
        this.uaaBaseUrl = uaaBaseUrl;
        this.idpZone = idpZone;
        this.spZone = spZone;
    }

    public void create() {
        createZones(adminToken, uaaBaseUrl);
        registerIdentityProvider();
        registerServiceProvider();
    }

    private void createZones(String adminToken, String url) {
        IdentityZoneUtils.createZone(adminToken, url, idpZone, idpZone, new IdentityZoneConfiguration());
        IdentityZoneUtils.createZone(adminToken, url, spZone, spZone, new IdentityZoneConfiguration());
    }

    private void registerServiceProvider() {
        SamlIntegrationTestUtils.createServiceProvider(adminToken, uaaBaseUrl, "notused", spZone, idpZone);
    }

    private void registerIdentityProvider() {
        idpRegistration = SamlIntegrationTestUtils.createUaaSamlIdentityProvider(idpZone, uaaBaseUrl, idpZone, spZone);
    }

    public void cleanup() {
        IdentityProviderUtils.deleteServiceProviderByNameIfExists(adminToken, uaaBaseUrl, idpZone, spZone);
        IdentityZoneUtils.deleteZoneIfExists(adminToken, uaaBaseUrl, idpZone);
        IdentityZoneUtils.deleteZoneIfExists(adminToken, uaaBaseUrl, spZone);
    }

    public ScimUser createUserInIdpZone(String username) {
        return UserUtils.createUser(
            adminToken, uaaBaseUrl, username, username, username, username + "@test.org", true, idpZone
        );
    }

    public IdentityProvider<SamlIdentityProviderDefinition> getIdpRegistration() {
        return idpRegistration;
    }
}
