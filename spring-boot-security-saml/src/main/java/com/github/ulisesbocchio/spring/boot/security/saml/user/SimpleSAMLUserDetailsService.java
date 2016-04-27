package com.github.ulisesbocchio.spring.boot.security.saml.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * Simple pass through User Details Service
 */
public class SimpleSAMLUserDetailsService implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        return new SAMLUserDetails(credential);
    }
}
