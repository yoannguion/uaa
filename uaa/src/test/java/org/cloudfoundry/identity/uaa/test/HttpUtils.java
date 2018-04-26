package org.cloudfoundry.identity.uaa.test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpUtils {
    public static String prependSubdomain(String url, String subdomain) {
        Matcher matcher = Pattern.compile("(https?://)(.*)").matcher(url);
        if (matcher.matches()) {
            url = String.format("%s%s.%s", matcher.group(1), subdomain, matcher.group(2));
        }
        return url;
    }
}
