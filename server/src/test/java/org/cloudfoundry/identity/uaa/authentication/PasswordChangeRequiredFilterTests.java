package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import java.util.HashSet;

import static java.util.Collections.emptyList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class PasswordChangeRequiredFilterTests {
    private UaaAuthentication authentication;

    @InjectMocks
    private PasswordChangeRequiredFilter passwordChangeRequiredFilter;
    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;
    @Mock
    private AuthenticationEntryPoint mockAuthenticationEntryPoint;
    @Mock
    private FilterChain mockFilterChain;

    @BeforeEach
    void setUp() {
        authentication = new UaaAuthentication(
                new UaaPrincipal("fake-id", "fake-username", "email@email.com", "origin", "", "uaa"),
                emptyList(),
                null
        );
        authentication.setAuthenticationMethods(new HashSet<>());
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletResponse = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void passwordChangeRequired() throws Exception {
        authentication.setRequiresPasswordChange(true);
        passwordChangeRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verifyZeroInteractions(mockFilterChain);
        verify(mockAuthenticationEntryPoint, times(1)).commence(same(mockHttpServletRequest), same(mockHttpServletResponse), any(InteractionRequiredException.class));
    }

    @Test
    void passwordChangeNotRequired() throws Exception {
        passwordChangeRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verifyZeroInteractions(mockAuthenticationEntryPoint);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }

    @Test
    void noAuthentication() throws Exception {
        SecurityContextHolder.clearContext();
        passwordChangeRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verifyZeroInteractions(mockAuthenticationEntryPoint);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }
}