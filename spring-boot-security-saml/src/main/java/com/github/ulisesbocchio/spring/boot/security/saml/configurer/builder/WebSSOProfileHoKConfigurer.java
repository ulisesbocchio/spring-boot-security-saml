package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileHoKImpl;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileHoKConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {
    private WebSSOProfileHoKImpl hokProfile;
    private WebSSOProfileHoKImpl hokProfileBean;

    public WebSSOProfileHoKConfigurer() {

    }

    public WebSSOProfileHoKConfigurer(WebSSOProfileHoKImpl hokProfile) {
        this.hokProfile = hokProfile;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        hokProfileBean = builder.getSharedObject(WebSSOProfileHoKImpl.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (hokProfileBean == null) {
            if (hokProfile == null) {
                hokProfile = new WebSSOProfileHoKImpl();
            }
            builder.setSharedObject(WebSSOProfileHoKImpl.class, hokProfile);
        }
    }
}
