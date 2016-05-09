package com.github.ulisesbocchio.spring.boot.security.saml.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * Simple pass through User Details Service.
 * Consider implementing your own {@link UserDetailsService} to check user permissions against a persistent storage and
 * load your own {@link UserDetails} implementation.
 *
 * @author Ulises Bocchio
 */
public class SimpleSAMLUserDetailsService implements SAMLUserDetailsService {
    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        return new SAMLUserDetails(credential);
    }
}
