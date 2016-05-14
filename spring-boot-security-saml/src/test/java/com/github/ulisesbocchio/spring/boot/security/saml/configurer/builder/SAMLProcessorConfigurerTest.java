package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties.SAMLProcessorConfiguration;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.processor.*;

import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@SuppressWarnings("unchecked")
public class SAMLProcessorConfigurerTest {
    private ServiceProviderSecurityBuilder builder;
    private ParserPool parserPool;
    private SAMLSSOProperties properties;
    private SAMLProcessorConfiguration samlProcessorConfig;

    @Before
    public void setup() {
        properties = mock(SAMLSSOProperties.class);
        samlProcessorConfig = spy(new SAMLProcessorConfiguration());
        when(properties.getSamlProcessor()).thenReturn(samlProcessorConfig);
        builder = mock(ServiceProviderSecurityBuilder.class);
        parserPool = mock(ParserPool.class);
        when(builder.getSharedObject(ParserPool.class)).thenReturn(parserPool);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        SAMLProcessorConfigurer configurer = new SAMLProcessorConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(SAMLProcessor.class));
    }

    @Test
    public void configure_forBean() throws Exception {
        SAMLProcessorConfigurer configurer = spy(new SAMLProcessorConfigurer());
        SAMLProcessorImpl profile = mock(SAMLProcessorImpl.class);
        when(builder.getSharedObject(SAMLProcessor.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSamlProcessor(anyListOf(SAMLBinding.class));
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile, samlProcessorConfig);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        SAMLProcessorImpl profile = mock(SAMLProcessorImpl.class);
        SAMLProcessorConfigurer configurer = spy(new SAMLProcessorConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSamlProcessor(anyListOf(SAMLBinding.class));
        verify(builder).setSharedObject(SAMLProcessor.class, profile);
        verifyZeroInteractions(profile, samlProcessorConfig);
    }

    @Test
    public void configure_defaults() throws Exception {
        SAMLProcessorConfigurer configurer = spy(new SAMLProcessorConfigurer());
        SAMLProcessorImpl profile = mock(SAMLProcessorImpl.class);
        when(configurer.createDefaultSamlProcessor(anyListOf(SAMLBinding.class))).thenReturn(profile);
        HTTPArtifactBinding artifactBinding = mock(HTTPArtifactBinding.class);
        doReturn(artifactBinding).when(configurer).createDefaultArtifactBinding();
        HTTPPAOS11Binding paosBinding = mock(HTTPPAOS11Binding.class);
        doReturn(paosBinding).when(configurer).createDefaultPaosBinding();
        HTTPPostBinding postBinding = mock(HTTPPostBinding.class);
        doReturn(postBinding).when(configurer).createDefaultPostBinding();
        HTTPRedirectDeflateBinding redirectBinding = mock(HTTPRedirectDeflateBinding.class);
        doReturn(redirectBinding).when(configurer).createDefaultRedirectBinding();
        HTTPSOAP11Binding soapBinding = mock(HTTPSOAP11Binding.class);
        doReturn(soapBinding).when(configurer).createDefaultSoapBinding();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLProcessor.class), eq(profile));
        verify(samlProcessorConfig).isArtifact();
        verify(samlProcessorConfig).isPaos();
        verify(samlProcessorConfig).isPost();
        verify(samlProcessorConfig).isRedirect();
        verify(samlProcessorConfig).isSoap();
        ArgumentCaptor<List> bindingsCaptor = ArgumentCaptor.forClass(List.class);
        verify(configurer).createDefaultSamlProcessor(bindingsCaptor.capture());
        List<SAMLBinding> bindings = bindingsCaptor.getValue();
        Assertions.assertThat(bindings).contains(artifactBinding, paosBinding, postBinding, redirectBinding, soapBinding);
    }

    @Test
    public void configure_custom_bindings() throws Exception {
        SAMLProcessorConfigurer configurer = spy(new SAMLProcessorConfigurer());
        SAMLProcessorImpl profile = mock(SAMLProcessorImpl.class);
        when(configurer.createDefaultSamlProcessor(anyListOf(SAMLBinding.class))).thenReturn(profile);
        HTTPArtifactBinding artifactBinding = mock(HTTPArtifactBinding.class);
        HTTPPAOS11Binding paosBinding = mock(HTTPPAOS11Binding.class);
        HTTPPostBinding postBinding = mock(HTTPPostBinding.class);
        HTTPRedirectDeflateBinding redirectBinding = mock(HTTPRedirectDeflateBinding.class);
        HTTPSOAP11Binding soapBinding = mock(HTTPSOAP11Binding.class);
        configurer
                .artifactBinding(artifactBinding)
                .paosBinding(paosBinding)
                .postBinding(postBinding)
                .redirectBinding(redirectBinding)
                .soapBinding(soapBinding);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLProcessor.class), eq(profile));
        verify(samlProcessorConfig, never()).isArtifact();
        verify(samlProcessorConfig, never()).isPaos();
        verify(samlProcessorConfig, never()).isPost();
        verify(samlProcessorConfig, never()).isRedirect();
        verify(samlProcessorConfig, never()).isSoap();
        ArgumentCaptor<List> bindingsCaptor = ArgumentCaptor.forClass(List.class);
        verify(configurer).createDefaultSamlProcessor(bindingsCaptor.capture());
        List<SAMLBinding> bindings = bindingsCaptor.getValue();
        Assertions.assertThat(bindings).contains(artifactBinding, paosBinding, postBinding, redirectBinding, soapBinding);
    }

    @Test
    public void configure_disabled_bindings() throws Exception {
        SAMLProcessorConfigurer configurer = spy(new SAMLProcessorConfigurer());
        SAMLProcessorImpl profile = mock(SAMLProcessorImpl.class);
        when(configurer.createDefaultSamlProcessor(anyListOf(SAMLBinding.class))).thenReturn(profile);
        configurer
                .disableRedirectBinding()
                .disableArtifactBinding()
                .disablePaosBinding()
                .disablePostBinding()
                .disableSoapBinding();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLProcessor.class), eq(profile));
        verify(samlProcessorConfig, never()).isArtifact();
        verify(samlProcessorConfig, never()).isPaos();
        verify(samlProcessorConfig, never()).isPost();
        verify(samlProcessorConfig, never()).isRedirect();
        verify(samlProcessorConfig, never()).isSoap();
        ArgumentCaptor<List> bindingsCaptor = ArgumentCaptor.forClass(List.class);
        verify(configurer).createDefaultSamlProcessor(bindingsCaptor.capture());
        List<SAMLBinding> bindings = bindingsCaptor.getValue();
        Assertions.assertThat(bindings).isEmpty();
    }
}