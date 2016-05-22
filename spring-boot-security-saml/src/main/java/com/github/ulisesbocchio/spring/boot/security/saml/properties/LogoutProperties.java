package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;

/**
 * Configuration Properties Local and Global Logout.
 *
 * @author Ulises Bocchio
 */
@Data
public class LogoutProperties {

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative
     * to the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name
     * (such as "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also
     * supported.
     */
    private String defaultTargetURL = "/";

    /**
     * Sets the URL used to determine if the {@link SAMLLogoutFilter} is invoked.
     */
    private String logoutURL = "/saml/logout";

    /**
     * Sets the URL used to determine if the {@link SAMLLogoutProcessingFilter} is invoked.
     */
    private String singleLogoutURL = "saml/SingleLogout";

    /**
     * If true, removes the Authentication from the SecurityContext to prevent issues with concurrent requests.
     */
    private boolean clearAuthentication = true;

    /**
     * Causes the HttpSession to be invalidated when this LogoutHandler is invoked. Defaults to true.
     */
    private boolean invalidateSession = false;
}
