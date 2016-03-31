package com.ulisesbocchio.security.saml.spring.security;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Ulises Bocchio
 */
@Slf4j
@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

  public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
    log.info("Login received for user {}", credential.getNameID().getValue());
    return new SAMLUserDetails(credential);
  }
}
