package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileECPConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {
    private WebSSOProfileECPImpl ecpProfile;
    private WebSSOProfileECPImpl ecpProfileBean;

    public WebSSOProfileECPConfigurer() {

    }

    public WebSSOProfileECPConfigurer(WebSSOProfileECPImpl ecpProfile) {
        this.ecpProfile = ecpProfile;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        ecpProfileBean = builder.getSharedObject(WebSSOProfileECPImpl.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (ecpProfileBean == null) {
            if (ecpProfile == null) {
                ecpProfile = new WebSSOProfileECPImpl();
            }
            builder.setSharedObject(WebSSOProfileECPImpl.class, ecpProfile);
        }
    }
}
