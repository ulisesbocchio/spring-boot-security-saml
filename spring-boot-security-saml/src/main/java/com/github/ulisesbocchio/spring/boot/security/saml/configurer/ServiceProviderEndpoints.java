package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import lombok.Data;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Class for internal usage of this Spring Boot Plugin. It holds user configured endpoint URLS registered throughout
 * the Service Provider configuration using either the Java DSL or configuration properties. The endpoint URLs are held
 * so they can later be used to configure Spring Security request mappers properly.
 *
 * @author Ulises Bocchio
 */
@Data
public class ServiceProviderEndpoints {
    private String defaultFailureURL;
    private String ssoProcessingURL;
    private String discoveryProcessingURL;
    private String idpSelectionPageURL;
    private String ssoLoginURL;
    private String metadataURL;
    private String defaultTargetURL;
    private String logoutURL;
    private String singleLogoutURL;

    /**
     * Returns an {@link OrRequestMatcher} that contains all the different URLs configured throughout the Service
     * Provider configuration.
     * @return
     */
    public RequestMatcher getRequestMatcher() {
        return new OrRequestMatcher(requestMatchers(defaultFailureURL, ssoProcessingURL, discoveryProcessingURL,
                idpSelectionPageURL, ssoLoginURL, metadataURL, defaultTargetURL, logoutURL, singleLogoutURL));
    }

    private List<RequestMatcher> requestMatchers(String... patterns) {
        return Stream.of(patterns)
                .filter(p -> p != null)
                .map(AntPathRequestMatcher::new)
                .collect(Collectors.toList());
    }
}
