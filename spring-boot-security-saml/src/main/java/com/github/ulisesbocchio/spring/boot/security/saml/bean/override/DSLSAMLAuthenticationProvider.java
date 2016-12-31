package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.util.Assert;

/**
 * {@link SAMLAuthenticationProvider} with non-required autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLSAMLAuthenticationProvider extends SAMLAuthenticationProvider {

    /**
     * Logger for SAML events, cannot be null, must be set.
     *
     * @param samlLogger logger
     */
    @Override
    @Autowired(required = false)
    public void setSamlLogger(SAMLLogger samlLogger) {
        Assert.notNull(samlLogger, "SAMLLogger can't be null");
        this.samlLogger = samlLogger;
    }

    /**
     * Profile for consumption of processed messages, must be set.
     *
     * @param consumer consumer
     */
    @Override
    @Autowired(required = false)
    @Qualifier("webSSOprofileConsumer")
    public void setConsumer(WebSSOProfileConsumer consumer) {
        Assert.notNull(consumer, "WebSSO Profile Consumer can't be null");
        this.consumer = consumer;
    }

    /**
     * Profile for consumption of processed messages using the Holder-of-Key profile, must be set.
     *
     * @param hokConsumer holder-of-key consumer
     */
    @Override
    @Autowired(required = false)
    @Qualifier("hokWebSSOprofileConsumer")
    public void setHokConsumer(WebSSOProfileConsumer hokConsumer) {
        this.hokConsumer = hokConsumer;
    }
}
