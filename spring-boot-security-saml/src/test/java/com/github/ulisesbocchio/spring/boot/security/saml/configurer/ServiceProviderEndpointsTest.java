package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.junit.Test;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderEndpointsTest {
    @Test
    public void matchers() throws Exception {
        ServiceProviderEndpoints endpoints = new ServiceProviderEndpoints();
        endpoints.setDefaultFailureURL("/failure");
        endpoints.setIdpSelectionPageURL("/idp");
        endpoints.setSsoLoginURL("/login");
        endpoints.setDiscoveryProcessingURL("/discovery");
        endpoints.setDefaultTargetURL("/default");
        endpoints.setLogoutURL("/logout");
        endpoints.setMetadataURL("/metadata");
        endpoints.setSingleLogoutURL("/slo");
        endpoints.setSsoHoKProcessingURL("/hok");
        endpoints.setSsoProcessingURL("/sso");

        RequestMatcher matcher = endpoints.getRequestMatcher();
        assertThat(matcher.matches(mockRequest("/failure"))).isTrue();
        assertThat(matcher.matches(mockRequest("/idp"))).isTrue();
        assertThat(matcher.matches(mockRequest("/login"))).isTrue();
        assertThat(matcher.matches(mockRequest("/discovery"))).isTrue();
        assertThat(matcher.matches(mockRequest("/default"))).isTrue();
        assertThat(matcher.matches(mockRequest("/logout"))).isTrue();
        assertThat(matcher.matches(mockRequest("/metadata"))).isTrue();
        assertThat(matcher.matches(mockRequest("/slo"))).isTrue();
        assertThat(matcher.matches(mockRequest("/hok"))).isTrue();
        assertThat(matcher.matches(mockRequest("/sso"))).isTrue();

        assertThat(matcher.matches(mockRequest("/sanity-check"))).isFalse();
    }

    protected HttpServletRequest mockRequest(String path) {
        HttpServletRequest failureRequest = mock(HttpServletRequest.class);
        when(failureRequest.getMethod()).thenReturn("GET");
        when(failureRequest.getServletPath()).thenReturn(path);
        return failureRequest;
    }
}