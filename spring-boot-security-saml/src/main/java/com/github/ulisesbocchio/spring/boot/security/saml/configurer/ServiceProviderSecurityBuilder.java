package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAML2SsoProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.resource.SpringResourceWrapperOpenSAMLResource;
import com.github.ulisesbocchio.spring.boot.security.saml.user.SAMLUserDetails;
import lombok.SneakyThrows;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer>{

    public ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    @Override
    protected ServiceProviderSecurityConfigurer performBuild() throws Exception {
        getOrApply(new MetadataManagerConfigurer());
        MetadataManager metadataManager = getSharedObject(MetadataManager.class);

        getOrApply(new AuthenticationProviderConfigurer());
        SAMLAuthenticationProvider authenticationProvider = getSharedObject(SAMLAuthenticationProvider.class);

        getOrApply(new SAMLProcessorConfigurer());
        SAMLProcessor samlProcessor = getSharedObject(SAMLProcessor.class);

        return new ServiceProviderSecurityConfigurer(metadataManager, authenticationProvider, samlProcessor);
    }

    public MetadataManagerConfigurer metadataManager(MetadataManager metadataManager) throws Exception {
        setSharedObject(MetadataManager.class, metadataManager);
        return getOrApply(new MetadataManagerConfigurer());
    }

    public MetadataManagerConfigurer metadataManager() throws Exception {
        setSharedObject(MetadataManager.class, new CachingMetadataManager(null));
        return getOrApply(new MetadataManagerConfigurer());
    }

    private <C extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>> C getOrApply(
            C configurer) throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }

    public AuthenticationProviderConfigurer authenticationProvider() throws Exception {
        setSharedObject(SAMLAuthenticationProvider.class, new SAMLAuthenticationProvider());
        return getOrApply(new AuthenticationProviderConfigurer());
    }

    public AuthenticationProviderConfigurer authenticationProvider(SAMLAuthenticationProvider provider) throws Exception {
        setSharedObject(SAMLAuthenticationProvider.class, provider);
        return getOrApply(new AuthenticationProviderConfigurer());
    }

    public SAMLProcessorConfigurer sAMLProcessor(SAMLProcessor sAMLProcessor) throws Exception {
        setSharedObject(SAMLProcessor.class, sAMLProcessor);
        return getOrApply(new SAMLProcessorConfigurer());
    }

    public SAMLProcessorConfigurer sAMLProcessor() throws Exception {
        setSharedObject(SAMLProcessor.class, new SAMLProcessorImpl((Collection<SAMLBinding>) null));
        return getOrApply(new SAMLProcessorConfigurer());
    }

    /**
     * Configures Metadata Manager
     */
     public static class MetadataManagerConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

        List<MetadataProvider> metadataProviders = new ArrayList<>();
        private MetadataFilter metadataFilter = null;
        private ExtendedMetadata extendedMetadata = null;
        private Boolean forceMetadataRevocationCheck = null;
        private Boolean metadataRequireSignature = null;
        private Boolean metadataTrustCheck = null;
        private Set<String> metadataTrustedKeys = null;
        private Boolean requireValidMetadata = null;

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            MetadataManager metadataManager = builder.getSharedObject(MetadataManager.class);
            if(metadataProviders.size() == 0) {
                String metadataLocation = builder.getSharedObject(SAML2SsoProperties.class).getMetadataLocation();
                MetadataProvider defaultProvider = new ResourceBackedMetadataProvider(new Timer(),
                        new SpringResourceWrapperOpenSAMLResource(new ClassPathResource(metadataLocation)));
                metadataProviders.add(defaultProvider);
            }
            List<MetadataProvider> extendedMetadataDelegates = metadataProviders.stream()
                .map(this::setParserPool)
                .map(this::getExtendedProvider)
                .collect(Collectors.toList());
            metadataManager.setProviders(extendedMetadataDelegates);
        }

        private MetadataProvider setParserPool(MetadataProvider provider) {
            if(provider instanceof AbstractMetadataProvider) {
                ((AbstractMetadataProvider) provider).setParserPool(getBuilder().getSharedObject(ParserPool.class));
            }
            return provider;
        }

        @SneakyThrows
        private ExtendedMetadataDelegate getExtendedProvider(MetadataProvider provider) {
            if(provider instanceof ExtendedMetadataDelegate) {
                return (ExtendedMetadataDelegate) provider;
            }
            if(extendedMetadata == null) {
                extendedMetadata = getBuilder().getSharedObject(ExtendedMetadata.class);
            }
            ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, extendedMetadata);
            SAML2SsoProperties.ExtendedMetadataDelegateConfiguration extendedDelegate = getBuilder().getSharedObject(SAML2SsoProperties.class).getExtendedDelegate();

            if(forceMetadataRevocationCheck == null) {
                forceMetadataRevocationCheck = extendedDelegate.isForceMetadataRevocationCheck();
            }
            extendedMetadataDelegate.setForceMetadataRevocationCheck(forceMetadataRevocationCheck);

            if(metadataRequireSignature == null) {
                metadataRequireSignature = extendedDelegate.isMetadataRequireSignature();
            }
            extendedMetadataDelegate.setMetadataRequireSignature(metadataRequireSignature);

            if(metadataTrustCheck == null) {
                metadataTrustCheck = extendedDelegate.isMetadataTrustCheck();
            }
            extendedMetadataDelegate.setMetadataTrustCheck(metadataTrustCheck);

            if(metadataTrustedKeys == null) {
                metadataTrustedKeys = extendedDelegate.getMetadataTrustedKeys();
            }
            extendedMetadataDelegate.setMetadataTrustedKeys(metadataTrustedKeys);

            if(requireValidMetadata == null) {
                requireValidMetadata = extendedDelegate.isRequireValidMetadata();
            }
            extendedMetadataDelegate.setRequireValidMetadata(requireValidMetadata);

            if(metadataFilter != null) {
                metadataFilter = postProcess(metadataFilter);
            }
            extendedMetadataDelegate.setMetadataFilter(metadataFilter);

            return postProcess(extendedMetadataDelegate);
        }

        public MetadataManagerConfigurer metadataProvider(MetadataProvider provider) {
            metadataProviders.add(provider);
            return this;
        }

        public ServiceProviderSecurityBuilder metadataProviders(MetadataProvider... providers) {
            metadataProviders = Arrays.asList(providers);
            return getBuilder();
        }

        public ServiceProviderSecurityBuilder metadataProviders(List<MetadataProvider> providers) {
            metadataProviders = new ArrayList<>(providers);
            return getBuilder();
        }

        public MetadataManagerConfigurer metadataFilter(MetadataFilter filter) {
            metadataFilter = filter;
            return this;
        }

        public MetadataManagerConfigurer extendedMetadata(ExtendedMetadata extendedMetadata) {
            getBuilder().setSharedObject(ExtendedMetadata.class, extendedMetadata);
            this.extendedMetadata = extendedMetadata;
            return this;
        }

        public MetadataManagerConfigurer forceMetadataRevocationCheck(boolean forceMetadataRevocationCheck) {
            this.forceMetadataRevocationCheck = forceMetadataRevocationCheck;
            return this;
        }

        public MetadataManagerConfigurer metadataRequireSignature(boolean metadataRequireSignature) {
            this.metadataRequireSignature = metadataRequireSignature;
            return this;
        }

        public MetadataManagerConfigurer metadataTrustCheck(boolean metadataTrustCheck) {
            this.metadataTrustCheck = metadataTrustCheck;
            return this;
        }

        public MetadataManagerConfigurer metadataTrustedKeys(Set<String> metadataTrustedKeys) {
            this.metadataTrustedKeys = metadataTrustedKeys;
            return this;
        }

        public MetadataManagerConfigurer requireValidMetadata(boolean requireValidMetadata) {
            this.requireValidMetadata = requireValidMetadata;
            return this;
        }
    }

    /**
     * Configures Authentication Provider
     */
    public static class AuthenticationProviderConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

        private Boolean excludeCredential = null;
        private Boolean forcePrincipalAsString = null;
        private SAMLUserDetailsService userDetailsService;

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            SAMLAuthenticationProvider authenticationProvider = builder.getSharedObject(SAMLAuthenticationProvider.class);
            SAML2SsoProperties config = builder.getSharedObject(SAML2SsoProperties.class);

            if(excludeCredential == null) {
                excludeCredential = config.getAuthenticationProvider().isExcludeCredential();
            }
            authenticationProvider.setExcludeCredential(excludeCredential);

            if(forcePrincipalAsString == null) {
                forcePrincipalAsString = config.getAuthenticationProvider().isForcePrincipalAsString();
            }
            authenticationProvider.setForcePrincipalAsString(forcePrincipalAsString);

            if(userDetailsService == null) {
                userDetailsService = new SimpleSAMLUserDetailsService();
            }
            authenticationProvider.setUserDetails(postProcess(userDetailsService));
        }

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
            super.init(builder);
        }

        public AuthenticationProviderConfigurer excludeCredential(boolean excludeCredential) {
            getBuilder().getSharedObject(SAMLAuthenticationProvider.class).setExcludeCredential(excludeCredential);
            return this;
        }

        public AuthenticationProviderConfigurer forcePrincipalAsString(boolean forcePrincipalAsString) {
            getBuilder().getSharedObject(SAMLAuthenticationProvider.class).setForcePrincipalAsString(forcePrincipalAsString);
            return this;
        }

        public AuthenticationProviderConfigurer userDetailsService(SAMLUserDetailsService userDetailsService) {
            this.userDetailsService = userDetailsService;
            return this;
        }
    }

    /**
     * Configures SAML Processor
     */
    public static class SAMLProcessorConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

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

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
            super.init(builder);
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            SAML2SsoProperties.SAMLProcessorConfiguration processorConfig = builder.getSharedObject(SAML2SsoProperties.class).getSamlProcessor();
            ParserPool parserPool = builder.getSharedObject(ParserPool.class);
            List<SAMLBinding> bindings = new ArrayList<>();

            if(Optional.ofNullable(redirect).orElseGet(processorConfig::isRedirect)) {
                bindings.add(postProcess(new HTTPRedirectDeflateBinding(parserPool)));
            }

            if(Optional.ofNullable(post).orElseGet(processorConfig::isRedirect)) {
                bindings.add(postProcess(new HTTPPostBinding(parserPool, VelocityFactory.getEngine())));
            }

            if(Optional.ofNullable(artifact).orElseGet(processorConfig::isArtifact)) {
                HttpClient httpClient = new HttpClient(new MultiThreadedHttpConnectionManager());
                ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
                HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(parserPool);
                artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));
                bindings.add(postProcess(new HTTPArtifactBinding(parserPool, VelocityFactory.getEngine(), artifactResolutionProfile)));
            }

            if(Optional.ofNullable(soap).orElseGet(processorConfig::isSoap)) {
                bindings.add(postProcess(new HTTPSOAP11Binding(parserPool)));
            }

            if(Optional.ofNullable(paos).orElseGet(processorConfig::isPaos)) {
                bindings.add(postProcess(new HTTPPAOS11Binding(parserPool)));
            }

            builder.setSharedObject(SAMLProcessor.class, new SAMLProcessorImpl(bindings));
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

    /**
     * Simple pass through User Details Service
     */
    public static class SimpleSAMLUserDetailsService implements SAMLUserDetailsService {

        @Override
        public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
            return new SAMLUserDetails(credential);
        }
    }

}
