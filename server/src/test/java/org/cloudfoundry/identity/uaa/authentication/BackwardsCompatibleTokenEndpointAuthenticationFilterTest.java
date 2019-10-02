package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.TokenTestSupport;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthCodeToken;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import java.util.Collections;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class BackwardsCompatibleTokenEndpointAuthenticationFilterTest {

    private AuthenticationManager mockAuthenticationManager;
    private SAMLProcessingFilter mockSAMLProcessingFilter;
    private XOAuthAuthenticationManager mockXOAuthAuthenticationManager;
    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;
    private FilterChain mockFilterChain;
    private AuthenticationEntryPoint mockAuthenticationEntryPoint;

    private BackwardsCompatibleTokenEndpointAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        mockAuthenticationManager = mock(AuthenticationManager.class);
        OAuth2RequestFactory mockOAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        mockSAMLProcessingFilter = mock(SAMLProcessingFilter.class);
        mockXOAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);

        filter = spy(
                new BackwardsCompatibleTokenEndpointAuthenticationFilter(
                        mockAuthenticationManager,
                        mockOAuth2RequestFactory,
                        mockSAMLProcessingFilter,
                        mockXOAuthAuthenticationManager
                )
        );

        mockAuthenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(mockAuthenticationEntryPoint);

        mockHttpServletRequest = new MockHttpServletRequest("POST", "/oauth/token");
        mockHttpServletResponse = new MockHttpServletResponse();
        mockFilterChain = mock(FilterChain.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void password_expired() throws Exception {
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        when(uaaAuthentication.isAuthenticated()).thenReturn(true);
        when(uaaAuthentication.isRequiresPasswordChange()).thenReturn(true);
        when(mockAuthenticationManager.authenticate(any())).thenReturn(uaaAuthentication);
        mockHttpServletRequest.addParameter(GRANT_TYPE, "password");
        mockHttpServletRequest.addParameter("username", "marissa");
        mockHttpServletRequest.addParameter("password", "koala");
        filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockAuthenticationEntryPoint, times(1)).commence(same(mockHttpServletRequest), same(mockHttpServletResponse), any(PasswordChangeRequiredException.class));
    }

    @Test
    void attempt_password_authentication() throws Exception {
        mockHttpServletRequest.addParameter(GRANT_TYPE, "password");
        mockHttpServletRequest.addParameter("username", "marissa");
        mockHttpServletRequest.addParameter("password", "koala");
        filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(filter, times(1)).attemptTokenAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verify(mockAuthenticationManager, times(1)).authenticate(any());
        verifyZeroInteractions(mockSAMLProcessingFilter);
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
    }

    @Test
    void attempt_saml_assertion_authentication() throws Exception {
        mockHttpServletRequest.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        mockHttpServletRequest.addParameter("assertion", "saml-assertion-value-here");
        filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(filter, times(1)).attemptTokenAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verify(mockSAMLProcessingFilter, times(1)).attemptAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verifyZeroInteractions(mockAuthenticationManager);
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
    }

    @Test
    void saml_assertion_missing() throws Exception {
        mockHttpServletRequest.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(filter, times(1)).attemptTokenAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
        verifyZeroInteractions(mockAuthenticationManager);
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(mockAuthenticationEntryPoint, times(1)).commence(same(mockHttpServletRequest), same(mockHttpServletResponse), exceptionArgumentCaptor.capture());
        assertNotNull(exceptionArgumentCaptor.getValue());
        assertEquals("SAML Assertion is missing", exceptionArgumentCaptor.getValue().getMessage());
        assertTrue(exceptionArgumentCaptor.getValue() instanceof InsufficientAuthenticationException);
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WithSupport {

        private TokenTestSupport support;

        @BeforeEach
        void setUp() throws Exception {
            support = new TokenTestSupport(null);
        }

        @AfterEach
        void tearDown() {
            support.clear();
        }

        @Test
        void attempt_jwt_token_authentication() throws Exception {
            String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
            mockHttpServletRequest.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
            mockHttpServletRequest.addParameter("assertion", idToken);
            filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
            verify(filter, times(1)).attemptTokenAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
            ArgumentCaptor<XOAuthCodeToken> authenticateData = ArgumentCaptor.forClass(XOAuthCodeToken.class);
            verify(mockXOAuthAuthenticationManager, times(1)).authenticate(authenticateData.capture());
            verifyZeroInteractions(mockAuthenticationManager);
            verifyZeroInteractions(mockXOAuthAuthenticationManager);
            assertEquals(idToken, authenticateData.getValue().getIdToken());
            assertNull(authenticateData.getValue().getOrigin());
        }
    }

    @Test
    void jwt_assertion_missing() throws Exception {
        mockHttpServletRequest.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        filter.doFilter(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(filter, times(1)).attemptTokenAuthentication(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
        verifyZeroInteractions(mockAuthenticationManager);
        verifyZeroInteractions(mockXOAuthAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(mockAuthenticationEntryPoint, times(1)).commence(same(mockHttpServletRequest), same(mockHttpServletResponse), exceptionArgumentCaptor.capture());
        assertNotNull(exceptionArgumentCaptor.getValue());
        assertEquals("Assertion is missing", exceptionArgumentCaptor.getValue().getMessage());
        assertTrue(exceptionArgumentCaptor.getValue() instanceof InsufficientAuthenticationException);
    }

}