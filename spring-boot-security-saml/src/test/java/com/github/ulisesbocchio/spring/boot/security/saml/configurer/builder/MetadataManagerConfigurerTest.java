package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.ExtendedMetadataDelegateProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.IdentityProvidersProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.MetadataManagerProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.hamcrest.MockitoHamcrest;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@SuppressWarnings("unchecked")
public class MetadataManagerConfigurerTest {
    private ServiceProviderBuilder builder;
    private MetadataManagerProperties metadataManagerProperties;
    private ExtendedMetadataDelegateProperties extendedMetadataDelegateProperties;
    private SAMLSSOProperties properties;
    private ExtendedMetadata extendedMetadata;
    private IdentityProvidersProperties idpConfiguration;
    private ResourceLoader resourceLoader;
    private ParserPool parserPool;

    @Before
    public void setup() {
        properties = mock(SAMLSSOProperties.class);
        metadataManagerProperties = spy(new MetadataManagerProperties());
        extendedMetadataDelegateProperties = spy(new ExtendedMetadataDelegateProperties());
        idpConfiguration = spy(new IdentityProvidersProperties());
        extendedMetadata = spy(new ExtendedMetadata());
        when(properties.getMetadataManager()).thenReturn(metadataManagerProperties);
        when(properties.getExtendedDelegate()).thenReturn(extendedMetadataDelegateProperties);
        when(properties.getIdp()).thenReturn(idpConfiguration);
        builder = mock(ServiceProviderBuilder.class);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
        when(builder.getSharedObject(ExtendedMetadata.class)).thenReturn(extendedMetadata);
        resourceLoader = new DefaultResourceLoader();
        when(builder.getSharedObject(ResourceLoader.class)).thenReturn(resourceLoader);
        parserPool = mock(ParserPool.class);
        when(builder.getSharedObject(ParserPool.class)).thenReturn(parserPool);
    }

    @Test
    public void init() throws Exception {
        MetadataManagerConfigurer configurer = new MetadataManagerConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(MetadataManager.class));
        verify(builder, atLeastOnce()).getSharedObject(eq(SAMLSSOProperties.class));
        verify(builder).getSharedObject(eq(ResourceLoader.class));
        verify(properties).getMetadataManager();
        verify(properties).getExtendedDelegate();
    }

    @Test
    public void configure_bean() throws Exception {
        MetadataManager metadataManager = mock(MetadataManager.class);
        when(builder.getSharedObject(MetadataManager.class)).thenReturn(metadataManager);
        MetadataManagerConfigurer configurer = new MetadataManagerConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verifyZeroInteractions(metadataManagerProperties, extendedMetadata);
        verify(builder, never()).setSharedObject(eq(MetadataManager.class), any());
    }

    @Test
    public void configure_constructor() throws Exception {
        MetadataManager metadataManager = mock(MetadataManager.class);
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer(metadataManager));
        configurer.setBuilder(builder);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer).createDefaultMetadataProvider(eq(idpConfiguration.getMetadataLocation()));
        verify(configurer).createDefaultExtendedMetadataDelegate(any(ResourceBackedMetadataProvider.class), any());
        verify(metadataManagerProperties, never()).getDefaultIdp();
        verify(metadataManagerProperties, never()).getHostedSpName();
        verify(metadataManagerProperties, never()).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isExactlyInstanceOf(ExtendedMetadataDelegate.class);
        assertThat(((ExtendedMetadataDelegate) providers.get(0)).getDelegate()).isExactlyInstanceOf(ResourceBackedMetadataProvider.class);
    }

    @Test
    public void configure_defaults() throws Exception {
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer());
        CachingMetadataManager metadataManager = mock(CachingMetadataManager.class);
        when(configurer.createDefaultMetadataManager()).thenReturn(metadataManager);
        ExtendedMetadataDelegate delegate = mock(ExtendedMetadataDelegate.class);
        doReturn(delegate).when(configurer).createDefaultExtendedMetadataDelegate(any(), any());
        configurer.setBuilder(builder);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer).createDefaultMetadataProvider(eq(idpConfiguration.getMetadataLocation()));
        verify(configurer).createDefaultExtendedMetadataDelegate(any(ResourceBackedMetadataProvider.class), any());
        verify(metadataManagerProperties).getDefaultIdp();
        verify(metadataManagerProperties).getHostedSpName();
        verify(metadataManagerProperties).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isEqualTo(delegate);
        verify(metadataManager).setDefaultIDP(eq(metadataManagerProperties.getDefaultIdp()));
        verify(metadataManager).setHostedSPName(eq(metadataManagerProperties.getHostedSpName()));
        verify(metadataManager).setRefreshCheckInterval(eq(metadataManagerProperties.getRefreshCheckInterval()));
        verify(delegate).setForceMetadataRevocationCheck(eq(extendedMetadataDelegateProperties.isForceMetadataRevocationCheck()));
        verify(delegate).setMetadataRequireSignature(eq(extendedMetadataDelegateProperties.isMetadataRequireSignature()));
        verify(delegate).setMetadataTrustCheck(eq(extendedMetadataDelegateProperties.isMetadataTrustCheck()));
        verify(delegate).setMetadataTrustedKeys(eq(extendedMetadataDelegateProperties.getMetadataTrustedKeys()));
        verify(delegate).setRequireValidMetadata(eq(extendedMetadataDelegateProperties.isRequireValidMetadata()));
        verify(delegate).setMetadataFilter((MetadataFilter) isNull());
    }

    @Test
    public void configure_defaults_withProvider() throws Exception {
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer());
        CachingMetadataManager metadataManager = mock(CachingMetadataManager.class);
        when(configurer.createDefaultMetadataManager()).thenReturn(metadataManager);
        configurer.setBuilder(builder);
        AbstractMetadataProvider provider = mock(AbstractMetadataProvider.class);
        configurer.metadataProvider(provider);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(provider).setParserPool(eq(parserPool));
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer, never()).createDefaultMetadataProvider(eq(idpConfiguration.getMetadataLocation()));
        verify(configurer, never()).createDefaultExtendedMetadataDelegate(any(ResourceBackedMetadataProvider.class), any());
        verify(metadataManagerProperties).getDefaultIdp();
        verify(metadataManagerProperties).getHostedSpName();
        verify(metadataManagerProperties).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isExactlyInstanceOf(ExtendedMetadataDelegate.class);
        assertThat(((ExtendedMetadataDelegate) providers.get(0)).getDelegate()).isEqualTo(provider);
    }

    @Test
    public void configure_defaults_withProviderDelegate() throws Exception {
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer());
        CachingMetadataManager metadataManager = mock(CachingMetadataManager.class);
        when(configurer.createDefaultMetadataManager()).thenReturn(metadataManager);
        configurer.setBuilder(builder);
        MetadataProvider provider = mock(ExtendedMetadataDelegate.class);
        configurer.metadataProvider(provider);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer, never()).createDefaultMetadataProvider(eq(idpConfiguration.getMetadataLocation()));
        verify(configurer, never()).createDefaultExtendedMetadataDelegate(any(ResourceBackedMetadataProvider.class), any());
        verify(metadataManagerProperties).getDefaultIdp();
        verify(metadataManagerProperties).getHostedSpName();
        verify(metadataManagerProperties).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties, never()).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties, never()).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties, never()).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties, never()).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties, never()).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isEqualTo(provider);
        assertThat(((ExtendedMetadataDelegate) providers.get(0)).getDelegate()).isNull();
    }

    @Test
    public void configure_defaults_withProviderLocation() throws Exception {
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer());
        CachingMetadataManager metadataManager = mock(CachingMetadataManager.class);
        when(configurer.createDefaultMetadataManager()).thenReturn(metadataManager);
        configurer.setBuilder(builder);
        configurer.metadataLocations("classpath:idp-provided.xml");
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer).createDefaultMetadataProvider(eq("classpath:idp-provided.xml"));
        verify(configurer).createDefaultExtendedMetadataDelegate(any(ResourceBackedMetadataProvider.class), any());
        verify(metadataManagerProperties).getDefaultIdp();
        verify(metadataManagerProperties).getHostedSpName();
        verify(metadataManagerProperties).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isExactlyInstanceOf(ExtendedMetadataDelegate.class);
        assertThat(((ExtendedMetadataDelegate) providers.get(0)).getDelegate()).isExactlyInstanceOf(ResourceBackedMetadataProvider.class);
    }

    @Test
    public void configure_arguments() throws Exception {
        MetadataManagerConfigurer configurer = spy(new MetadataManagerConfigurer());
        CachingMetadataManager metadataManager = mock(CachingMetadataManager.class);
        when(configurer.createDefaultMetadataManager()).thenReturn(metadataManager);
        ResourceBackedMetadataProvider provider = mock(ResourceBackedMetadataProvider.class);
        doReturn(provider).when(configurer).createDefaultMetadataProvider("classpath:idp-provided.xml");
        ExtendedMetadataDelegate delegate = mock(ExtendedMetadataDelegate.class);
        doReturn(delegate).when(configurer).createDefaultExtendedMetadataDelegate(eq(provider), any(ExtendedMetadata.class));
        MetadataFilter metadataFilter = mock(MetadataFilter.class);
        configurer.setBuilder(builder);
        configurer
                .metadataLocations("classpath:idp-provided.xml")
                .defaultIDP("default")
                .hostedSPName("spname")
                .refreshCheckInterval(999L)
                .forceMetadataRevocationCheck(true)
                .metadataRequireSignature(true)
                .metadataTrustCheck(true)
                .requireValidMetadata(true)
                .metadataTrustedKeys("one", "two")
                .metadataFilter(metadataFilter);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(MetadataManager.class), eq(metadataManager));
        ArgumentCaptor<List> providersCaptor = ArgumentCaptor.forClass(List.class);
        verify(metadataManager).setProviders((List<MetadataProvider>) providersCaptor.capture());
        verify(configurer).createDefaultMetadataProvider(eq("classpath:idp-provided.xml"));
        verify(configurer).createDefaultExtendedMetadataDelegate(eq(provider), any());
        verify(metadataManagerProperties, never()).getDefaultIdp();
        verify(metadataManagerProperties, never()).getHostedSpName();
        verify(metadataManagerProperties, never()).getRefreshCheckInterval();
        verify(extendedMetadataDelegateProperties, never()).isForceMetadataRevocationCheck();
        verify(extendedMetadataDelegateProperties, never()).isMetadataRequireSignature();
        verify(extendedMetadataDelegateProperties, never()).isMetadataTrustCheck();
        verify(extendedMetadataDelegateProperties, never()).isRequireValidMetadata();
        verify(extendedMetadataDelegateProperties, never()).getMetadataTrustedKeys();
        List<MetadataProvider> providers = providersCaptor.getValue();
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0)).isEqualTo(delegate);
        verify(metadataManager).setDefaultIDP(eq("default"));
        verify(metadataManager).setHostedSPName(eq("spname"));
        verify(metadataManager).setRefreshCheckInterval(eq(999L));
        verify(delegate).setForceMetadataRevocationCheck(eq(true));
        verify(delegate).setMetadataRequireSignature(eq(true));
        verify(delegate).setMetadataTrustCheck(eq(true));
        verify(delegate).setMetadataTrustedKeys((Set<String>) MockitoHamcrest.argThat(contains("one", "two")));
        verify(delegate).setRequireValidMetadata(eq(true));
        verify(delegate).setMetadataFilter(eq(metadataFilter));
    }

}