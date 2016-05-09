package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;

/**
 * Builder configurer that takes care of configuring/customizing the {@link WebSSOProfileECPImpl} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link WebSSOProfileECPImpl} bean is defined, priority goes to a custom WebSSOProfileECPImpl provided
 * explicitly to this configurer through the constructor. And if not provided through the constructor, a default
 * implementation is instantiated.
 * </p>
 *
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
