package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class PasswordChangeRequiredFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint entryPoint;

    public PasswordChangeRequiredFilter(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(
            final @NonNull HttpServletRequest request,
            final @NonNull HttpServletResponse response,
            final @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (needsPasswordReset()) {
            entryPoint.commence(request,
                    response,
                    new PasswordChangeRequiredException(
                            (UaaAuthentication) getContext().getAuthentication(),
                            "password reset is required"
                    )
            );
        } else {
            //pass through
            filterChain.doFilter(request, response);
        }
    }

    private boolean needsPasswordReset() {
        Authentication authentication = getContext().getAuthentication();
        return authentication instanceof UaaAuthentication &&
                ((UaaAuthentication) authentication).isRequiresPasswordChange() &&
                authentication.isAuthenticated();
    }
}
