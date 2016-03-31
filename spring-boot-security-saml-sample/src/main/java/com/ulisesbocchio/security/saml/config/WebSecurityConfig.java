package com.ulisesbocchio.security.saml.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

/**
 * @author Ulises Bocchio
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SAMLLogoutFilter samlLogoutFilter;

    @Autowired
    private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;

    @Autowired
    private MetadataDisplayFilter metadataDisplayFilter;

    @Autowired
    private MetadataGeneratorFilter metadataGeneratorFilter;

    @Autowired
    private SAMLProcessingFilter samlWebSSOProcessingFilter;

    @Autowired
    private SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter;

    @Autowired
    private SAMLEntryPoint samlEntryPoint;

    @Autowired
    private SAMLDiscovery samlIDPDiscovery;

    @Autowired
    private AuthenticationManager authenticationManager;


    @Override
    public void init(WebSecurity web) throws Exception {
        super.init(web);
    }


    /**
     * Defines the web based security configuration.
     *
     * @param http It allows configuring web based security for specific http requests.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
        securityContextRepository.setSpringSecurityContextKey("SPRING_SECURITY_CONTEXT_SAML");
        http
                .securityContext()
                .securityContextRepository(securityContextRepository);
        http
                .httpBasic()
                .disable();
        http
                .csrf()
                .disable();
        http
                .addFilterAfter(metadataGeneratorFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(metadataDisplayFilter, MetadataGeneratorFilter.class)
                .addFilterAfter(samlEntryPoint, MetadataDisplayFilter.class)
                .addFilterAfter(samlWebSSOProcessingFilter, SAMLEntryPoint.class)
                .addFilterAfter(samlWebSSOHoKProcessingFilter, SAMLProcessingFilter.class)
                .addFilterAfter(samlLogoutProcessingFilter, SAMLWebSSOHoKProcessingFilter.class)
                .addFilterAfter(samlIDPDiscovery, SAMLLogoutProcessingFilter.class)
                .addFilterAfter(samlLogoutFilter, LogoutFilter.class);
        http
                .authorizeRequests()
                .antMatchers("/", "/error", "/saml/**", "/idpselection").permitAll()
                .anyRequest().authenticated();
        http
                .exceptionHandling()
                .authenticationEntryPoint(samlEntryPoint);
        http
                .logout()
                .disable();
    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return authenticationManager;
    }
}
