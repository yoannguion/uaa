package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class UserUtils {
    public static ScimUser getUserById(String adminToken, String uaaUrl, String zoneSubdomain, String userId) {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity<Object> request = new HttpEntity<>(headers);

        return restTemplate.exchange(uaaUrl + "/Users/{id}", HttpMethod.GET, request, ScimUser.class, userId).getBody();
    }

    public static ScimUser getUserByName(String adminToken, String uaaUrl, String zoneSubdomain, String username) {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity<Object> request = new HttpEntity<>(headers);

        ParameterizedTypeReference<SearchResults<ScimUser>> parameterizedTypeReference =
            new ParameterizedTypeReference<SearchResults<ScimUser>>() {}; //OMG

        SearchResults<ScimUser> response =
            restTemplate.exchange(uaaUrl + "/Users", HttpMethod.GET, request, parameterizedTypeReference)
                .getBody();
        List<ScimUser> users = response.getResources();
        for (ScimUser user : users) {
            if (user != null && user.getUserName().equals(username)) {
                return user;
            }
        }
        return null;
    }

    public static ScimUser createUser(String adminToken,
                                      String uaaUrl,
                                      String username,
                                      String firstName,
                                      String lastName,
                                      String email,
                                      boolean verified,
                                      String zoneSubdomain) {
        return createUserWithPhone(
            adminToken, uaaUrl, username, firstName, lastName, email, verified, null, zoneSubdomain
        );
    }

    private static ScimUser createUserWithPhone(String adminToken,
                                                String uaaUrl,
                                                String username,
                                                String firstName,
                                                String lastName,
                                                String email,
                                                boolean verified,
                                                String phoneNumber,
                                                String zoneSubdomain) {

        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);

        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("koala");
        user.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber(phoneNumber)));

        HttpEntity<ScimUser> request = new HttpEntity<ScimUser>(user, headers);
        return restTemplate.exchange(uaaUrl + "/Users", HttpMethod.POST, request, ScimUser.class).getBody();
    }
}
