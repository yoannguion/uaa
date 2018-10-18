/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;

public class DisableIdTokenResponseTypeFilterTest {

    private DisableIdTokenResponseTypeFilter filter;
    private DisableIdTokenResponseTypeFilter disabledFilter;
    private List<String> applyPaths = Arrays.asList("/oauth/authorze", "/**/oauth/authorize");
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    private ArgumentCaptor<HttpServletRequest> captor = ArgumentCaptor.forClass(HttpServletRequest.class);
    private FilterChain chain = mock(FilterChain.class);

    @Before
    public void setUp() {
        filter = new DisableIdTokenResponseTypeFilter(false, applyPaths);
        disabledFilter = new DisableIdTokenResponseTypeFilter(true, applyPaths);
        request.setPathInfo("/oauth/authorize");
    }

    @Test
    public void testIsIdTokenDisabled() {
        assertFalse(filter.isIdTokenDisabled());
        assertTrue(disabledFilter.isIdTokenDisabled());
    }

    @Test
    public void applyPath() {
        shouldApplyPath("/oauth/token", false);
        shouldApplyPath("/someotherpath/uaa/oauth/authorize", true);
        shouldApplyPath("/uaa/oauth/authorize", true);
        shouldApplyPath("/oauth/authorize", true);
        shouldApplyPath(null, false);
        shouldApplyPath("", false);
    }

    private void shouldApplyPath(String path, boolean expectedOutCome) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo(path);
        assertEquals(expectedOutCome, filter.applyPath(path));
        assertEquals(expectedOutCome, disabledFilter.applyPath(path));
    }

    @Test
    public void doFilterInternal_NO_Response_Type_Parameter() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertSame(request, captor.getValue());
        reset(chain);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertNotSame(request, captor.getValue());
    }

    @Test
    public void doFilterInternal_Code_Response_Type_Parameter() throws Exception {
        String responseType = "code";
        validate_filter(responseType, responseType);
    }

    @Test
    public void doFilterInternal_Code_and_IdToken_Response_Type_Parameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    public void doFilterInternal_IdToken_and_Code_Response_Type_Parameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    public void doFilterInternal_Token_and_IdToken_and_Code_Response_Type_Parameter() throws Exception {
        String responseType = "token code id_token";
        String removedType = "token code";
        validate_filter(responseType, removedType);
    }

    private void validate_filter(String responseType, String removedType) throws Exception {
        request.addParameter(RESPONSE_TYPE, responseType);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertSame(request, captor.getValue());
        reset(chain);
        assertEquals(responseType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertNotSame(request, captor.getValue());
        assertEquals(removedType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(removedType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(removedType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);
    }

}