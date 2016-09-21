package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilderResult;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;

/**
 * Builder configurer that takes care of configuring/customizing the {@link WebSSOProfileConsumer} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link WebSSOProfileConsumer} bean is defined, priority goes to a custom WebSSOProfileConsumer provided
 * explicitly to this configurer through the constructor. And if not provided through the constructor, a default
 * implementation is instantiated.
 * </p>
 *
 * @author Ulises Bocchio
 */
public class WebSSOProfileConsumerConfigurer extends SecurityConfigurerAdapter<ServiceProviderBuilderResult, ServiceProviderBuilder> {

    private WebSSOProfileConsumer webSSOProfileConsumer;
    private WebSSOProfileConsumer webSSOProfileConsumerBean;

    public WebSSOProfileConsumerConfigurer() {

    }

    public WebSSOProfileConsumerConfigurer(WebSSOProfileConsumer webSSOProfileConsumer) {
        this.webSSOProfileConsumer = webSSOProfileConsumer;
    }

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        webSSOProfileConsumerBean = builder.getSharedObject(WebSSOProfileConsumer.class);
    }

    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        if (webSSOProfileConsumerBean == null) {
            if (webSSOProfileConsumer == null) {
                webSSOProfileConsumer = createWebSSOProfileConsumer();
            }
            builder.setSharedObject(WebSSOProfileConsumer.class, webSSOProfileConsumer);
        }
    }

    protected WebSSOProfileConsumer createWebSSOProfileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }
}