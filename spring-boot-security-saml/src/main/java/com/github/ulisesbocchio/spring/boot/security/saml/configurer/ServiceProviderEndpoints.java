package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import lombok.Data;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
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
