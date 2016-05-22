package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

/**
 * Configuration Properties for {@link org.springframework.security.saml.processor.SAMLProcessor}
 *
 * @author Ulises Bocchio
 */
@Data
public class SAMLProcessorProperties {

    /**
     * Disable/Enable HTTP Redirect Bindings.
     */
    private boolean redirect = true;

    /**
     * Disable/Enable HTTP POST Bindings.
     */
    private boolean post = true;

    /**
     * Disable/Enable HTTP Artifact Bindings.
     */
    private boolean artifact = true;

    /**
     * Disable/Enable SOAP Bindings.
     */
    private boolean soap = true;

    /**
     * Disable/Enable PAOS Bindings.
     */
    private boolean paos = true;
}
