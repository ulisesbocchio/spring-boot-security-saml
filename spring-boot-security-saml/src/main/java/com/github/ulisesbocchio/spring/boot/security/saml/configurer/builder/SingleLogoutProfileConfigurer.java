package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.assertj.core.util.VisibleForTesting;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

/**
 * Builder configurer that takes care of configuring/customizing the {@link SingleLogoutProfile} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link SingleLogoutProfile} bean is defined, priority goes to a custom SingleLogoutProfile provided
 * explicitly to this configurer through the constructor. And if not provided through the constructor, a default
 * implementation is instantiated.
 * </p>
 *
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
                sloProfile = createDefaultSingleLogoutProfile();
            }
            builder.setSharedObject(SingleLogoutProfile.class, sloProfile);
        }
    }

    @VisibleForTesting
    protected SingleLogoutProfile createDefaultSingleLogoutProfile() {
        return new SingleLogoutProfileImpl();
    }
}
