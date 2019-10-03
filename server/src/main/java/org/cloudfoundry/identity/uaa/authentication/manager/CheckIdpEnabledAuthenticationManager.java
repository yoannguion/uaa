package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CheckIdpEnabledAuthenticationManager implements AuthenticationManager {

    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final AuthenticationManager delegate;
    private final IdentityZoneManager identityZoneManager;

    public CheckIdpEnabledAuthenticationManager(
            final AuthenticationManager delegate,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final IdentityZoneManager identityZoneManager) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.delegate = delegate;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        try {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider \"" + idp.getName() + "\" has been disabled by administrator.");
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("Unable to find identity provider for origin: " + OriginKeys.UAA);
        }
        return delegate.authenticate(authentication);
    }
}
