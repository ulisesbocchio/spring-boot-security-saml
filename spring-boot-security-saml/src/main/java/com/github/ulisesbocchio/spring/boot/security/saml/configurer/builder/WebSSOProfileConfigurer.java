package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

/**
 * Builder configurer that takes care of configuring/customizing the {@link WebSSOProfile} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link WebSSOProfile} bean is defined, priority goes to a custom WebSSOProfile provided explicitly
 * to this configurer through the constructor. And if not provided through the constructor, a default implementation is
 * instantiated.
 * </p>
 *
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
