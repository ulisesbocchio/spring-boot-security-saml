package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileConsumerConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private WebSSOProfileConsumer webSSOProfileConsumer;
    private WebSSOProfileConsumer webSSOProfileConsumerBean;

    public WebSSOProfileConsumerConfigurer() {

    }

    public WebSSOProfileConsumerConfigurer(WebSSOProfileConsumer webSSOProfileConsumer) {
        this.webSSOProfileConsumer = webSSOProfileConsumer;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        webSSOProfileConsumerBean = builder.getSharedObject(WebSSOProfileConsumer.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (webSSOProfileConsumerBean == null) {
            if (webSSOProfileConsumer == null) {
                webSSOProfileConsumer = new WebSSOProfileConsumerImpl();
            }
            builder.setSharedObject(WebSSOProfileConsumer.class, webSSOProfileConsumer);
        }
    }
}