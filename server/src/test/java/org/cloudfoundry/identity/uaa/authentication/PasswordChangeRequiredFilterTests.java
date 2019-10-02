package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import java.util.HashSet;

import static java.util.Collections.emptyList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

public class PasswordChangeRequiredFilterTests {
    private UaaAuthentication authentication;
    private PasswordChangeRequiredFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthenticationEntryPoint entryPoint;
    private FilterChain chain;

    @Before
    public void setUp() {
        authentication = new UaaAuthentication(
                new UaaPrincipal("fake-id", "fake-username", "email@email.com", "origin", "", "uaa"),
                emptyList(),
                null
        );
        authentication.setAuthenticationMethods(new HashSet<>());
        entryPoint = mock(AuthenticationEntryPoint.class);
        chain = mock(FilterChain.class);
        filter = new PasswordChangeRequiredFilter(
                entryPoint
        );
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void passwordChangeRequired() throws Exception {
        authentication.setRequiresPasswordChange(true);
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(chain);
        verify(entryPoint, times(1)).commence(same(request), same(response), any(InteractionRequiredException.class));
    }

    @Test
    public void passwordChangeNotRequired() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(entryPoint);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void noAuthentication() throws Exception {
        SecurityContextHolder.clearContext();
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(entryPoint);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }
}