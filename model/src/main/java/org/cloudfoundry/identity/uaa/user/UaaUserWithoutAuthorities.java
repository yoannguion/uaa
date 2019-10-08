package org.cloudfoundry.identity.uaa.user;

import org.springframework.security.core.GrantedAuthority;

import java.util.Date;
import java.util.List;

public class UaaUserWithoutAuthorities extends UaaUser {

    public UaaUserWithoutAuthorities(UaaUserPrototype prototype) {
        super(prototype);
    }

    @Override
    public List<? extends GrantedAuthority> getAuthorities() {
        throw new IllegalStateException("UaaUser was made without authorities");
    }
}
