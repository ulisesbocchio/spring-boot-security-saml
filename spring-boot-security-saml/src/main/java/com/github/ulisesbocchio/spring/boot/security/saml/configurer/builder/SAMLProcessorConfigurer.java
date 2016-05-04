package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Configures SAML Processor
 */
public class SAMLProcessorConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private static VelocityEngine velocityEngine;
    private SAMLProcessor sAMLProcessor;
    private SAMLProcessor sAMLProcessorBean;
    private Boolean redirect = null;
    private Boolean post = null;
    private Boolean artifact = null;
    private Boolean soap = null;
    private Boolean paos = null;

    HTTPRedirectDeflateBinding redirectBinding;
    HTTPPostBinding postBinding;
    HTTPArtifactBinding artifactBinding;
    HTTPSOAP11Binding soapBinding;
    HTTPPAOS11Binding paosBinding;
    private SAMLSsoProperties.SAMLProcessorConfiguration processorConfig;
    private ParserPool parserPool;

    public SAMLProcessorConfigurer(SAMLProcessor sAMLProcessor) {
        this.sAMLProcessor = sAMLProcessor;
    }

    public SAMLProcessorConfigurer() {

    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        sAMLProcessorBean = builder.getSharedObject(SAMLProcessor.class);
        processorConfig = builder.getSharedObject(SAMLSsoProperties.class).getSamlProcessor();
        parserPool = builder.getSharedObject(ParserPool.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if(sAMLProcessorBean == null) {
            if(sAMLProcessor == null) {
                List<SAMLBinding> bindings = new ArrayList<>();

                if(Optional.ofNullable(redirect).orElseGet(processorConfig::isRedirect)) {
                    bindings.add(postProcess(new HTTPRedirectDeflateBinding(parserPool)));
                }

                if(Optional.ofNullable(post).orElseGet(processorConfig::isRedirect)) {
                    bindings.add(postProcess(new HTTPPostBinding(parserPool, getVelocityEngine())));
                }

                if(Optional.ofNullable(artifact).orElseGet(processorConfig::isArtifact)) {
                    HttpClient httpClient = new HttpClient(new MultiThreadedHttpConnectionManager());
                    ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
                    HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(parserPool);
                    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));
                    bindings.add(postProcess(new HTTPArtifactBinding(parserPool, getVelocityEngine(), artifactResolutionProfile)));
                }

                if(Optional.ofNullable(soap).orElseGet(processorConfig::isSoap)) {
                    bindings.add(postProcess(new HTTPSOAP11Binding(parserPool)));
                }

                if(Optional.ofNullable(paos).orElseGet(processorConfig::isPaos)) {
                    bindings.add(postProcess(new HTTPPAOS11Binding(parserPool)));
                }
                sAMLProcessor = new SAMLProcessorImpl(bindings);
            }

            builder.setSharedObject(SAMLProcessor.class, sAMLProcessor);
        }
    }

    private VelocityEngine getVelocityEngine() {
        if(velocityEngine == null) {
            velocityEngine = VelocityFactory.getEngine();
        }
        return velocityEngine;
    }

    public SAMLProcessorConfigurer disableRedirectBinding() {
        redirect = false;
        return this;
    }

    public SAMLProcessorConfigurer redirectBinding(HTTPRedirectDeflateBinding binding) {
        redirect = true;
        redirectBinding = binding;
        return this;
    }

    public SAMLProcessorConfigurer disablePostBinding() {
        post = false;
        return this;
    }

    public SAMLProcessorConfigurer postBinding(HTTPPostBinding binding) {
        post = true;
        postBinding = binding;
        return this;
    }

    public SAMLProcessorConfigurer disableArtifactBinding() {
        artifact = false;
        return this;
    }

    public SAMLProcessorConfigurer artifactBinding(HTTPArtifactBinding binding) {
        artifact = true;
        artifactBinding = binding;
        return this;
    }

    public SAMLProcessorConfigurer disableSoapBinding() {
        soap = false;
        return this;
    }

    public SAMLProcessorConfigurer soapBinding(HTTPSOAP11Binding binding) {
        soap = true;
        soapBinding = binding;
        return this;
    }

    public SAMLProcessorConfigurer disablePaosBinding() {
        paos = false;
        return this;
    }

    public SAMLProcessorConfigurer paosBinding(HTTPPAOS11Binding binding) {
        paos = true;
        paosBinding = binding;
        return this;
    }
}
