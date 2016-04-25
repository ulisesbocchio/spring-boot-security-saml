package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.resource.SpringResourceWrapperOpenSAMLResource;
import com.github.ulisesbocchio.spring.boot.security.saml.user.SAMLUserDetails;
import lombok.SneakyThrows;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
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
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

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

        getOrApply(new LogoutConfigurer());
        SAMLLogoutFilter samlLogoutFilter = getSharedObject(SAMLLogoutFilter.class);
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = getSharedObject(SAMLLogoutProcessingFilter.class);

        getOrApply(new MetadataManagerConfigurer());
        MetadataDisplayFilter metadataDisplayFilter = getSharedObject(MetadataDisplayFilter.class);
        MetadataGeneratorFilter metadataGeneratorFilter = getSharedObject(MetadataGeneratorFilter.class);

        return new ServiceProviderSecurityConfigurer(metadataManager, authenticationProvider, samlProcessor,
                samlLogoutFilter, samlLogoutProcessingFilter, metadataDisplayFilter, metadataGeneratorFilter);
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

    public LogoutConfigurer logout() throws Exception {
        return getOrApply(new LogoutConfigurer());
    }

    public MetadataGeneratorConfigurer metadataGenerator() throws Exception {
        return getOrApply(new MetadataGeneratorConfigurer());
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
        private List<String> metadataProviderLocations = new ArrayList<>();

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            MetadataManager metadataManager = builder.getSharedObject(MetadataManager.class);

            if(metadataProviders.size() == 0 && metadataProviderLocations.size() > 0) {
                for(String metadataLocation : metadataProviderLocations) {
                    MetadataProvider defaultProvider = new ResourceBackedMetadataProvider(new Timer(),
                            new SpringResourceWrapperOpenSAMLResource(new ClassPathResource(metadataLocation)));
                    metadataProviders.add(defaultProvider);
                }
            }

            if(metadataProviders.size() == 0) {
                String metadataLocation = builder.getSharedObject(SAMLSsoProperties.class).getIdps().getMetadataLocation();
                for(String location : metadataLocation.split(",")) {
                    MetadataProvider defaultProvider = new ResourceBackedMetadataProvider(new Timer(),
                            new SpringResourceWrapperOpenSAMLResource(new ClassPathResource(location.trim())));
                    metadataProviders.add(defaultProvider);
                }
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
            SAMLSsoProperties.ExtendedMetadataDelegateConfiguration extendedDelegate = getBuilder().getSharedObject(SAMLSsoProperties.class).getExtendedDelegate();

            extendedMetadataDelegate.setForceMetadataRevocationCheck(Optional.ofNullable(forceMetadataRevocationCheck)
                    .orElseGet(extendedDelegate::isForceMetadataRevocationCheck));

            extendedMetadataDelegate.setMetadataRequireSignature(Optional.ofNullable(metadataRequireSignature)
                    .orElseGet(extendedDelegate::isMetadataRequireSignature));

            extendedMetadataDelegate.setMetadataTrustCheck(Optional.ofNullable(metadataTrustCheck)
                    .orElseGet(extendedDelegate::isMetadataTrustCheck));

            extendedMetadataDelegate.setMetadataTrustedKeys(Optional.ofNullable(metadataTrustedKeys)
                    .orElseGet(extendedDelegate::getMetadataTrustedKeys));

            extendedMetadataDelegate.setRequireValidMetadata(Optional.ofNullable(requireValidMetadata)
                    .orElseGet(extendedDelegate::isRequireValidMetadata));

            extendedMetadataDelegate.setMetadataFilter(Optional.ofNullable(metadataFilter)
                    .map(this::postProcess)
                    .orElse(null));

            return postProcess(extendedMetadataDelegate);
        }

        public MetadataManagerConfigurer metadataProvider(MetadataProvider provider) {
            metadataProviders.add(provider);
            return this;
        }

        public MetadataManagerConfigurer metadataProviders(MetadataProvider... providers) {
            metadataProviders = Arrays.asList(providers);
            return this;
        }

        public MetadataManagerConfigurer metadataProviderLocations(String... providerLocation) {
            metadataProviderLocations.addAll(Arrays.asList(providerLocation));
            return this;
        }

        public MetadataManagerConfigurer metadataProviders(List<MetadataProvider> providers) {
            metadataProviders = new ArrayList<>(providers);
            return this;
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
            SAMLSsoProperties config = builder.getSharedObject(SAMLSsoProperties.class);

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
            SAMLSsoProperties.SAMLProcessorConfiguration processorConfig = builder.getSharedObject(SAMLSsoProperties.class).getSamlProcessor();
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
     * Configures the Logout aspect of the SAML Service Provider
     */
    public static class LogoutConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {
        private String defaultTargetURL;
        private String logoutURL;
        private String singleLogoutURL;
        private Boolean clearAuthentication;
        private Boolean invalidateSession;
        private LogoutSuccessHandler successHandler;
        private LogoutHandler localHandler;
        private LogoutHandler globalHandler;

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
            super.init(builder);
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            SAMLSsoProperties.LogoutConfiguration config = builder.getSharedObject(SAMLSsoProperties.class).getLogout();

            if(successHandler == null) {
                SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
                successLogoutHandler.setDefaultTargetUrl(Optional.ofNullable(defaultTargetURL).orElseGet(config::getDefaultTargetURL));
                successHandler = successLogoutHandler;
            }

            if(localHandler == null) {
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                logoutHandler.setInvalidateHttpSession(Optional.ofNullable(invalidateSession).orElseGet(config::isInvalidateSession));
                logoutHandler.setClearAuthentication(Optional.ofNullable(clearAuthentication).orElseGet(config::isClearAuthentication));
                localHandler = logoutHandler;
            }

            if(globalHandler == null) {
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                logoutHandler.setInvalidateHttpSession(Optional.ofNullable(invalidateSession).orElseGet(config::isInvalidateSession));
                logoutHandler.setClearAuthentication(Optional.ofNullable(clearAuthentication).orElseGet(config::isClearAuthentication));
                globalHandler = logoutHandler;
            }

            SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(successHandler, new LogoutHandler[]{localHandler}, new LogoutHandler[]{globalHandler});
            samlLogoutFilter.setFilterProcessesUrl(Optional.ofNullable(logoutURL).orElseGet(config::getLogoutURL));

            SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(successHandler, globalHandler);
            samlLogoutProcessingFilter.setFilterProcessesUrl(Optional.ofNullable(singleLogoutURL).orElseGet(config::getSingleLogoutURL));

            builder.setSharedObject(SAMLLogoutFilter.class, samlLogoutFilter);
            builder.setSharedObject(SAMLLogoutProcessingFilter.class, samlLogoutProcessingFilter);
        }

        public LogoutConfigurer defaultTargetURL(String url) {
            defaultTargetURL = url;
            return this;
        }

        public LogoutConfigurer logoutURL(String url) {
            logoutURL = url;
            return this;
        }

        public LogoutConfigurer singleLogoutURL(String url) {
            singleLogoutURL = url;
            return this;
        }

        public LogoutConfigurer clearAuthentication(Boolean value) {
            clearAuthentication = value;
            return this;
        }

        public LogoutConfigurer invalidateSession(Boolean value) {
            invalidateSession = value;
            return this;
        }

        public LogoutConfigurer successHandler(LogoutSuccessHandler handler) {
            successHandler = handler;
            return this;
        }

        public LogoutConfigurer localHandler(LogoutHandler handler) {
            localHandler = handler;
            return this;
        }

        public LogoutConfigurer globalHandler(LogoutHandler handler) {
            globalHandler = handler;
            return this;
        }
    }

    /**
     * Configures metadata generator filter for SAML Service Provider
     */
    public static class MetadataGeneratorConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

        private String metadataURL;
        private String entityId;
        private Boolean wantAssertionSigned;
        private Boolean requestSigned;
        private Collection<String> nameId;
        private String entityBaseURL;
        private Collection<String> bindingsHoKSSO;
        private Collection<String> bindingsSLO;
        private Collection<String> bindingsSSO;
        private Integer assertionConsumerIndex;
        private Boolean includeDiscoveryExtension;

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
            super.init(builder);
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {

            SAMLSsoProperties.MetadataGeneratorConfiguration config = builder.getSharedObject(SAMLSsoProperties.class).getMetadataGenerator();

            MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
            metadataDisplayFilter.setFilterProcessesUrl(Optional.ofNullable(metadataURL).orElseGet(config::getMetadataURL));

            MetadataGenerator metadataGenerator = new MetadataGenerator();
            metadataGenerator.setEntityId(Optional.ofNullable(entityId).orElseGet(config::getEntityId));
            metadataGenerator.setExtendedMetadata(builder.getSharedObject(ExtendedMetadata.class));
            metadataGenerator.setWantAssertionSigned(Optional.ofNullable(wantAssertionSigned).orElseGet(config::isWantAssertionSigned));
            metadataGenerator.setRequestSigned(Optional.ofNullable(requestSigned).orElseGet(config::isRequestSigned));
            metadataGenerator.setNameID(Optional.ofNullable(nameId).orElseGet(config::getNameId));
            metadataGenerator.setEntityBaseURL(Optional.ofNullable(entityBaseURL).orElseGet(config::getEntityBaseURL));
            metadataGenerator.setBindingsHoKSSO(Optional.ofNullable(bindingsHoKSSO).orElseGet(config::getBindingsHoKSSO));
            metadataGenerator.setBindingsSLO(Optional.ofNullable(bindingsSLO).orElseGet(config::getBindingsSLO));
            metadataGenerator.setBindingsSSO(Optional.ofNullable(bindingsSSO).orElseGet(config::getBindingsSSO));
            metadataGenerator.setAssertionConsumerIndex(Optional.ofNullable(assertionConsumerIndex).orElseGet(config::getAssertionConsumerIndex));
            metadataGenerator.setIncludeDiscoveryExtension(Optional.ofNullable(includeDiscoveryExtension).orElseGet(config::isIncludeDiscoveryExtension));

            MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(metadataGenerator);

            builder.setSharedObject(MetadataDisplayFilter.class, metadataDisplayFilter);
            builder.setSharedObject(MetadataGeneratorFilter.class, metadataGeneratorFilter);
        }

        public MetadataGeneratorConfigurer metadataURL(String metadataURL) {
            this.metadataURL = metadataURL;
            return this;
        }

        public MetadataGeneratorConfigurer entityId(String entityId) {
            this.entityId = entityId;
            return this;
        }

        public MetadataGeneratorConfigurer wantAssertionSigned(Boolean wantAssertionSigned) {
            this.wantAssertionSigned = wantAssertionSigned;
            return this;
        }

        public MetadataGeneratorConfigurer requestSigned(Boolean requestSigned) {
            this.requestSigned = requestSigned;
            return this;
        }

        public MetadataGeneratorConfigurer nameId(String... nameId) {
            this.nameId = Arrays.asList(nameId);
            return this;
        }

        public MetadataGeneratorConfigurer entityBaseURL(String entityBaseURL) {
            this.entityBaseURL = entityBaseURL;
            return this;
        }

        public MetadataGeneratorConfigurer bindingsHoKSSO(String... bindingsHoKSSO) {
            this.bindingsHoKSSO = Arrays.asList(bindingsHoKSSO);
            return this;
        }

        public MetadataGeneratorConfigurer bindingsSLO(String... bindingsSLO) {
            this.bindingsSLO = Arrays.asList(bindingsSLO);
            return this;
        }

        public MetadataGeneratorConfigurer bindingsSSO(String... bindingsSSO) {
            this.bindingsSSO = Arrays.asList(bindingsSSO);
            return this;
        }

        public MetadataGeneratorConfigurer assertionConsumerIndex(Integer assertionConsumerIndex) {
            this.assertionConsumerIndex = assertionConsumerIndex;
            return this;
        }

        public MetadataGeneratorConfigurer includeDiscoveryExtension(Boolean includeDiscoveryExtension) {
            this.includeDiscoveryExtension = includeDiscoveryExtension;
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
