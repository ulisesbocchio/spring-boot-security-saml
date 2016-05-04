package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private WebSSOProfile webSSOProfile;
    private WebSSOProfile webSSOProfileBean;

    public WebSSOProfileConfigurer() {

    }

    public WebSSOProfileConfigurer(WebSSOProfile webSSOProfile) {
        this.webSSOProfile = webSSOProfile;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        webSSOProfileBean = builder.getSharedObject(WebSSOProfile.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (webSSOProfileBean == null) {
            if (webSSOProfile == null) {
                webSSOProfile = new WebSSOProfileImpl();
            }
            builder.setSharedObject(WebSSOProfile.class, webSSOProfile);
        }
    }
}
