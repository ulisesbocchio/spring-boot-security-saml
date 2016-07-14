package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurerBeans;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileHoKImpl;

/**
 * Builder configurer that takes care of configuring/customizing the {@link WebSSOProfileHoKImpl} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link WebSSOProfileHoKImpl} bean is defined, priority goes to a custom WebSSOProfileHoKImpl provided
 * explicitly to this configurer through the constructor. And if not provided through the constructor, a default
 * implementation is instantiated.
 * </p>
 *
 * @author Ulises Bocchio
 */
public class WebSSOProfileHoKConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurerBeans, ServiceProviderSecurityBuilder> {
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
                hokProfile = createDefaultWebSSOProfileHoK();
            }
            builder.setSharedObject(WebSSOProfileHoKImpl.class, hokProfile);
        }
    }

    protected WebSSOProfileHoKImpl createDefaultWebSSOProfileHoK() {
        return new WebSSOProfileHoKImpl();
    }
}
