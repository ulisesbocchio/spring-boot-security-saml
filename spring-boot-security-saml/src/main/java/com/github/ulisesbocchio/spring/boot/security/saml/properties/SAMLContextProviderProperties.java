package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;

/**
 * Configuration Properties For {@link SAMLContextProvider}.
 *
 * @author Ulises Bocchio
 */
@Data
public class SAMLContextProviderProperties {

    /**
     * Enables Load Balancer configuration through {@link SAMLContextProviderLB}
     */
    @NestedConfigurationProperty
    private SAMLContextProviderLBProperties lb = new SAMLContextProviderLBProperties();
}
