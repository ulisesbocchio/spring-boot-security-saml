package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties.LogoutConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class LogoutConfigurerTest {

    private ServiceProviderSecurityBuilder builder;
    private LogoutConfiguration logoutConfiguration;
    private ServiceProviderEndpoints serviceProviderEndpoints;
    private SAMLSSOProperties properties;

    @Before
    public void setup() {
        properties = mock(SAMLSSOProperties.class);
        logoutConfiguration = spy(new LogoutConfiguration());
        serviceProviderEndpoints = spy(new ServiceProviderEndpoints());
        when(properties.getLogout()).thenReturn(logoutConfiguration);
        builder = mock(ServiceProviderSecurityBuilder.class);
        when(builder.getSharedObject(ServiceProviderEndpoints.class)).thenReturn(serviceProviderEndpoints);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        LogoutConfigurer configurer = new LogoutConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(ServiceProviderEndpoints.class));
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
        verify(properties).getLogout();
    }

    @Test
    public void configure_defaults() throws Exception {
        LogoutConfigurer configurer = spy(new LogoutConfigurer());
        SimpleUrlLogoutSuccessHandler successHandler = mock(SimpleUrlLogoutSuccessHandler.class);
        SecurityContextLogoutHandler localHandler = mock(SecurityContextLogoutHandler.class);
        SecurityContextLogoutHandler globalHandler = mock(SecurityContextLogoutHandler.class);
        when(configurer.createDefaultSuccessHandler()).thenReturn(successHandler);
        when(configurer.createDefaultLocalHandler()).thenReturn(localHandler);
        when(configurer.createDefaultGlobalHandler()).thenReturn(globalHandler);
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<SAMLLogoutFilter> logoutFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutFilter.class);
        ArgumentCaptor<SAMLLogoutProcessingFilter> logoutProcessingFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutProcessingFilter.class);
        verify(builder).setSharedObject(eq(SAMLLogoutFilter.class), logoutFilterCaptor.capture());
        verify(builder).setSharedObject(eq(SAMLLogoutProcessingFilter.class), logoutProcessingFilterCaptor.capture());
        verify(logoutConfiguration).getDefaultTargetURL();
        verify(logoutConfiguration, times(2)).isInvalidateSession();
        verify(logoutConfiguration, times(2)).isClearAuthentication();
        verify(logoutConfiguration).getLogoutURL();
        verify(logoutConfiguration).getSingleLogoutURL();
        verify(successHandler).setDefaultTargetUrl(eq(logoutConfiguration.getDefaultTargetURL()));
        verify(localHandler).setClearAuthentication(eq(logoutConfiguration.isClearAuthentication()));
        verify(localHandler).setInvalidateHttpSession(eq(logoutConfiguration.isInvalidateSession()));
        verify(globalHandler).setClearAuthentication(eq(logoutConfiguration.isClearAuthentication()));
        verify(globalHandler).setInvalidateHttpSession(eq(logoutConfiguration.isInvalidateSession()));
        SAMLLogoutFilter logoutFilter = logoutFilterCaptor.getValue();
        SAMLLogoutProcessingFilter logoutProcessingFilter = logoutProcessingFilterCaptor.getValue();
        assertThat(logoutFilter).isNotNull();
        assertThat(logoutProcessingFilter).isNotNull();
        assertThat(logoutFilter.getFilterProcessesUrl()).isEqualTo(logoutConfiguration.getLogoutURL());
        assertThat(logoutProcessingFilter.getFilterProcessesUrl()).isEqualTo(logoutConfiguration.getSingleLogoutURL());
        assertThat(serviceProviderEndpoints.getLogoutURL()).isEqualTo(logoutConfiguration.getLogoutURL());
        assertThat(serviceProviderEndpoints.getSingleLogoutURL()).isEqualTo(logoutConfiguration.getSingleLogoutURL());
    }

    @Test
    public void configure_handlers_defaults() throws Exception {
        LogoutConfigurer configurer = new LogoutConfigurer();
        SimpleUrlLogoutSuccessHandler successHandler = mock(SimpleUrlLogoutSuccessHandler.class);
        SecurityContextLogoutHandler localHandler = mock(SecurityContextLogoutHandler.class);
        SecurityContextLogoutHandler globalHandler = mock(SecurityContextLogoutHandler.class);
        configurer
                .successHandler(successHandler)
                .localHandler(localHandler)
                .globalHandler(globalHandler);
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<SAMLLogoutFilter> logoutFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutFilter.class);
        ArgumentCaptor<SAMLLogoutProcessingFilter> logoutProcessingFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutProcessingFilter.class);
        verify(builder).setSharedObject(eq(SAMLLogoutFilter.class), logoutFilterCaptor.capture());
        verify(builder).setSharedObject(eq(SAMLLogoutProcessingFilter.class), logoutProcessingFilterCaptor.capture());
        verify(logoutConfiguration, never()).getDefaultTargetURL();
        verify(logoutConfiguration, never()).isInvalidateSession();
        verify(logoutConfiguration, never()).isClearAuthentication();
        verify(logoutConfiguration).getLogoutURL();
        verify(logoutConfiguration).getSingleLogoutURL();
        verifyZeroInteractions(successHandler, localHandler, globalHandler);
        SAMLLogoutFilter logoutFilter = logoutFilterCaptor.getValue();
        SAMLLogoutProcessingFilter logoutProcessingFilter = logoutProcessingFilterCaptor.getValue();
        assertThat(logoutFilter).isNotNull();
        assertThat(logoutProcessingFilter).isNotNull();
        assertThat(logoutFilter.getFilterProcessesUrl()).isEqualTo(logoutConfiguration.getLogoutURL());
        assertThat(logoutProcessingFilter.getFilterProcessesUrl()).isEqualTo(logoutConfiguration.getSingleLogoutURL());
        assertThat(serviceProviderEndpoints.getLogoutURL()).isEqualTo(logoutConfiguration.getLogoutURL());
        assertThat(serviceProviderEndpoints.getSingleLogoutURL()).isEqualTo(logoutConfiguration.getSingleLogoutURL());
    }

    @Test
    public void configure_arguments() throws Exception {
        LogoutConfigurer configurer = spy(new LogoutConfigurer());
        SimpleUrlLogoutSuccessHandler successHandler = mock(SimpleUrlLogoutSuccessHandler.class);
        SecurityContextLogoutHandler localHandler = mock(SecurityContextLogoutHandler.class);
        SecurityContextLogoutHandler globalHandler = mock(SecurityContextLogoutHandler.class);
        when(configurer.createDefaultSuccessHandler()).thenReturn(successHandler);
        when(configurer.createDefaultLocalHandler()).thenReturn(localHandler);
        when(configurer.createDefaultGlobalHandler()).thenReturn(globalHandler);
        configurer
                .defaultTargetURL("/default")
                .clearAuthentication(false)
                .invalidateSession(true)
                .logoutURL("/lo")
                .singleLogoutURL("/slo");
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<SAMLLogoutFilter> logoutFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutFilter.class);
        ArgumentCaptor<SAMLLogoutProcessingFilter> logoutProcessingFilterCaptor = ArgumentCaptor.forClass(SAMLLogoutProcessingFilter.class);
        verify(builder).setSharedObject(eq(SAMLLogoutFilter.class), logoutFilterCaptor.capture());
        verify(builder).setSharedObject(eq(SAMLLogoutProcessingFilter.class), logoutProcessingFilterCaptor.capture());
        verify(logoutConfiguration, never()).getDefaultTargetURL();
        verify(logoutConfiguration, never()).isInvalidateSession();
        verify(logoutConfiguration, never()).isClearAuthentication();
        verify(logoutConfiguration, never()).getLogoutURL();
        verify(logoutConfiguration, never()).getSingleLogoutURL();
        verify(successHandler).setDefaultTargetUrl(eq("/default"));
        verify(localHandler).setClearAuthentication(eq(false));
        verify(localHandler).setInvalidateHttpSession(eq(true));
        verify(globalHandler).setClearAuthentication(eq(false));
        verify(globalHandler).setInvalidateHttpSession(eq(true));
        SAMLLogoutFilter logoutFilter = logoutFilterCaptor.getValue();
        SAMLLogoutProcessingFilter logoutProcessingFilter = logoutProcessingFilterCaptor.getValue();
        assertThat(logoutFilter).isNotNull();
        assertThat(logoutProcessingFilter).isNotNull();
        assertThat(logoutFilter.getFilterProcessesUrl()).isEqualTo("/lo");
        assertThat(logoutProcessingFilter.getFilterProcessesUrl()).isEqualTo("/slo");
        assertThat(serviceProviderEndpoints.getLogoutURL()).isEqualTo("/lo");
        assertThat(serviceProviderEndpoints.getSingleLogoutURL()).isEqualTo("/slo");
    }

}