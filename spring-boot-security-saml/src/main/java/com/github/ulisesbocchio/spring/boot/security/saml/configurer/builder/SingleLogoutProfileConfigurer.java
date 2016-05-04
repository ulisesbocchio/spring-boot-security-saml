package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

/**
 * @author Ulises Bocchio
 */
public class SingleLogoutProfileConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private SingleLogoutProfile sloProfile;
    private SingleLogoutProfile sloProfileBean;

    public SingleLogoutProfileConfigurer() {

    }

    public SingleLogoutProfileConfigurer(SingleLogoutProfile sloProfile) {
        this.sloProfile = sloProfile;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        sloProfileBean = builder.getSharedObject(SingleLogoutProfile.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (sloProfileBean == null) {
            if (sloProfile == null) {
                sloProfile = new SingleLogoutProfileImpl();
            }
            builder.setSharedObject(SingleLogoutProfile.class, sloProfile);
        }
    }
}
