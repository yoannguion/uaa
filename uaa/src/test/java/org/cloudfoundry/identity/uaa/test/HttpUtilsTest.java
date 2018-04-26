package org.cloudfoundry.identity.uaa.test;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class HttpUtilsTest {
    @Test
    public void prependSubdomain_Http() {
        String url = "http://localhost:8080/uaa";
        String newUrl = HttpUtils.prependSubdomain(url, "some-subdomain");

        assertEquals("http://some-subdomain.localhost:8080/uaa", newUrl);
    }

    @Test
    public void prependSubdomain_Https() {
        String url = "https://localhost:8443/uaa";
        String newUrl = HttpUtils.prependSubdomain(url, "some-subdomain");

        assertEquals("https://some-subdomain.localhost:8443/uaa", newUrl);
    }
}
