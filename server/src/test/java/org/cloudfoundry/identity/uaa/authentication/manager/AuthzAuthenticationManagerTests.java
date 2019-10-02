package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class AuthzAuthenticationManagerTests {
    private static final String PASSWORD = "password";
    private static final String LOGIN_SERVER_USER_NAME = "iHaVeUpPeRcAsE".toLowerCase();

    private AuthzAuthenticationManager authzAuthenticationManager;
    private UaaUserDatabase mockUaaUserDatabase;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private UaaUser uaaUser;
    private PasswordEncoder passwordEncoder;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private String currentZoneId;

    private ArgumentCaptor<ApplicationEvent> eventCaptor;
    private AccountLoginPolicy mockAccountLoginPolicy;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setUp() {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        currentZoneId = "currentZoneId-" + generator.generate();

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentZoneId);

        passwordEncoder = new PasswordEncoderConfig().nonCachingPasswordEncoder();
        uaaUser = new UaaUser(getPrototype());
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        mockUaaUserDatabase = mock(UaaUserDatabase.class);

        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        eventCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        doNothing().when(mockApplicationEventPublisher).publishEvent(eventCaptor.capture());
        mockAccountLoginPolicy = mock(AccountLoginPolicy.class);
        when(mockAccountLoginPolicy.isAllowed(any(), any())).thenReturn(true);

        authzAuthenticationManager = new AuthzAuthenticationManager(mockUaaUserDatabase, passwordEncoder, identityProviderProvisioning, mockIdentityZoneManager, mockAccountLoginPolicy, true);
        authzAuthenticationManager.setApplicationEventPublisher(mockApplicationEventPublisher);
    }

    private UaaUserPrototype getPrototype() {
        String id = new RandomValueStringGenerator().generate();
        return new UaaUserPrototype()
                .withId(id)
                .withUsername("auser")
                .withPassword(passwordEncoder.encode(PASSWORD))
                .withEmail("auser@blah.com")
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName("A")
                .withFamilyName("User")
                .withOrigin(OriginKeys.UAA)
                .withZoneId(currentZoneId)
                .withExternalId(id)
                .withPasswordLastModified(new Date(System.currentTimeMillis()))
                .withVerified(true);
    }

    @Test
    void successfulAuthentication() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication result = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
        assertNotNull(result);
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());
        assertThat(((UaaAuthentication) result).getAuthenticationMethods(), containsInAnyOrder("pwd"));

        List<ApplicationEvent> events = eventCaptor.getAllValues();
        assertThat(events.get(0), instanceOf(IdentityProviderAuthenticationSuccessEvent.class));
        assertEquals("auser", ((IdentityProviderAuthenticationSuccessEvent) events.get(0)).getUser().getUsername());
    }

    @Test
    void unsuccessfulPasswordExpired() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();

        UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition(new PasswordPolicy(6, 128, 1, 1, 1, 1, 6), null);
        provider.setConfig(idpDefinition);

        when(identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(provider);

        Calendar oneYearAgoCal = Calendar.getInstance();
        oneYearAgoCal.add(Calendar.YEAR, -1);
        Date oneYearAgo = new Date(oneYearAgoCal.getTimeInMillis());
        uaaUser = new UaaUser(
                uaaUser.getId(),
                uaaUser.getUsername(),
                passwordEncoder.encode(PASSWORD),
                uaaUser.getPassword(),
                uaaUser.getAuthorities(),
                uaaUser.getGivenName(),
                uaaUser.getFamilyName(),
                oneYearAgo,
                oneYearAgo,
                OriginKeys.UAA,
                null,
                true,
                currentZoneId,
                uaaUser.getSalt(),
                oneYearAgo);
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication authentication = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
        assertTrue(((UaaAuthentication) authentication).isRequiresPasswordChange());
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    void unsuccessfulLoginServerUserAuthentication() {
        when(mockUaaUserDatabase.retrieveUserByName(LOGIN_SERVER_USER_NAME, OriginKeys.UAA)).thenReturn(null);
        assertThrows(BadCredentialsException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest(LOGIN_SERVER_USER_NAME, "")));
        verify(mockUaaUserDatabase, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void unsuccessfulLoginServerUserWithPasswordAuthentication() {
        when(mockUaaUserDatabase.retrieveUserByName(LOGIN_SERVER_USER_NAME, OriginKeys.UAA)).thenReturn(null);
        assertThrows(BadCredentialsException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest(LOGIN_SERVER_USER_NAME, "dadas")));
    }

    @Test
    void successfulAuthenticationReturnsTokenAndPublishesEvent() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication result = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));

        assertNotNull(result);
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());

        verify(mockApplicationEventPublisher).publishEvent(isA(IdentityProviderAuthenticationSuccessEvent.class));
    }

    @Test
    void invalidPasswordPublishesAuthenticationFailureEvent() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);

        assertThrows(BadCredentialsException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("auser", "wrongpassword")));

        verify(mockApplicationEventPublisher).publishEvent(isA(IdentityProviderAuthenticationFailureEvent.class));
        verify(mockApplicationEventPublisher).publishEvent(isA(UserAuthenticationFailureEvent.class));
        verify(mockUaaUserDatabase, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void authenticationIsDeniedIfRejectedByLoginPolicy() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        when(mockAccountLoginPolicy.isAllowed(any(UaaUser.class), any(Authentication.class))).thenReturn(false);
        assertThrows(AuthenticationPolicyRejectionException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("auser", "password")));
        verify(mockUaaUserDatabase, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void missingUserPublishesNotFoundEvent() {
        when(mockUaaUserDatabase.retrieveUserByName(eq("aguess"), eq(OriginKeys.UAA))).thenThrow(new UsernameNotFoundException("mocked"));
        assertThrows(BadCredentialsException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("aguess", "password")));
        verify(mockApplicationEventPublisher).publishEvent(isA(UserNotFoundEvent.class));
    }

    @Test
    void originAuthenticationFail() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", "not UAA")).thenReturn(uaaUser);
        assertThrows(BadCredentialsException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("auser", "password")));
    }

    @Test
    void unverifiedAuthenticationForOldUserSucceedsWhenAllowed() {
        uaaUser = new UaaUser(getPrototype().withLegacyVerificationBehavior(true));
        uaaUser.setVerified(false);
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication result = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());
    }

    @Test
    void unverifiedAuthenticationForNewUserFailsEvenWhenAllowed() {
        uaaUser.setVerified(false);
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        assertThrows(AccountNotVerifiedException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("auser", "password")));
        verify(mockApplicationEventPublisher).publishEvent(isA(UnverifiedUserAuthenticationEvent.class));
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WithAllowUnverifiedUsersFalse {
        @BeforeEach
        void setUp() {
            authzAuthenticationManager = new AuthzAuthenticationManager(mockUaaUserDatabase, passwordEncoder, identityProviderProvisioning, mockIdentityZoneManager, mockAccountLoginPolicy, false);
            authzAuthenticationManager.setApplicationEventPublisher(mockApplicationEventPublisher);
        }

        @Test
        void authenticationWhenUserPasswordChangeRequired() {
            uaaUser.setPasswordChangeRequired(true);
            when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
            Authentication authentication = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
            assertTrue(((UaaAuthentication) authentication).isRequiresPasswordChange());
            assertTrue(authentication.isAuthenticated());
        }

        @Test
        void unverifiedAuthenticationFailsWhenNotAllowed() {
            uaaUser.setVerified(false);
            when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
            assertThrows(AccountNotVerifiedException.class, () -> authzAuthenticationManager.authenticate(createAuthRequest("auser", "password")));
            verify(mockApplicationEventPublisher).publishEvent(isA(UnverifiedUserAuthenticationEvent.class));
        }
    }

    @Test
    void testSystemWidePasswordExpiry() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();
        UaaIdentityProviderDefinition idpDefinition = mock(UaaIdentityProviderDefinition.class);
        provider.setConfig(idpDefinition);
        when(identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(provider);
        PasswordPolicy policy = new PasswordPolicy();
        policy.setPasswordNewerThan(new Date(System.currentTimeMillis() + 1000));
        when(idpDefinition.getPasswordPolicy()).thenReturn(policy);
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication authentication = authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
        assertTrue(((UaaAuthentication) authentication).isRequiresPasswordChange());
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    void testSystemWidePasswordExpiryWithPastDate() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();
        UaaIdentityProviderDefinition idpDefinition = mock(UaaIdentityProviderDefinition.class);
        provider.setConfig(idpDefinition);
        when(identityProviderProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(provider);
        PasswordPolicy policy = new PasswordPolicy();
        Date past = new Date(System.currentTimeMillis() - 10000000);
        policy.setPasswordNewerThan(past);
        when(idpDefinition.getPasswordPolicy()).thenReturn(policy);
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        authzAuthenticationManager.authenticate(createAuthRequest("auser", "password"));
    }

    @Test
    void userIsLockedOutAfterNumberOfUnsuccessfulTriesIsExceeded() {
        when(mockUaaUserDatabase.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(uaaUser);
        Authentication authentication = createAuthRequest("auser", "password");
        when(mockAccountLoginPolicy.isAllowed(any(UaaUser.class), eq(authentication))).thenReturn(false);

        assertThrows(AuthenticationPolicyRejectionException.class, () -> authzAuthenticationManager.authenticate(authentication));

        assertFalse(authentication.isAuthenticated());
        verify(mockApplicationEventPublisher).publishEvent(isA(AuthenticationFailureLockedEvent.class));
    }

    private static AuthzAuthenticationRequest createAuthRequest(String username, String password) {
        Map<String, String> userdata = new HashMap<>();
        userdata.put("username", username);
        userdata.put("password", password);
        return new AuthzAuthenticationRequest(userdata, new UaaAuthenticationDetails(mock(HttpServletRequest.class)));
    }
}