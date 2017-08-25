package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.security.saml.context.SAMLContextProviderLB;

/**
 * Configuration Properties For {@link SAMLContextProviderLB}.
 *
 * @author Ulises Bocchio
 */
@Data
public class SAMLContextProviderLBProperties {

    boolean enabled = false;

    /**
     * Scheme of the LB server - either http or https
     */
    private String scheme;

    /**
     * Server name of the LB, e.g. www.myserver.com
     */
    private String serverName;

    /**
     * When true serverPort will be used in construction of LB requestURL
     */
    private Boolean includeServerPortInRequestUrl;

    /**
     * Port of the server, in case value is &lt;= 0 port will not be included in the requestURL and port
     * from the original request will be used for getServerPort calls
     */
    private Integer serverPort;

    /**
     * Context path of the LB, must be starting with slash, e.g. /saml-extension
     */
    private String contextPath;

    /**
     * Scheme of the LB server - either http or https
     *
     * @param scheme scheme
     */
    public void setScheme(String scheme) {
        this.enabled = true;
        this.scheme = scheme;
    }

    /**
     * Server name of the LB, e.g. www.myserver.com
     *
     * @param serverName server name
     */
    public void setServerName(String serverName) {
        this.enabled = true;
        this.serverName = serverName;
    }

    /**
     * When true serverPort will be used in construction of LB requestURL.
     *
     * @param includeServerPortInRequestUrl true to include port
     */
    public void setIncludeServerPortInRequestUrl(boolean includeServerPortInRequestUrl) {
        this.enabled = true;
        this.includeServerPortInRequestUrl = includeServerPortInRequestUrl;
    }

    /**
     * Port of the server, in case value is &lt;= 0 port will not be included in the requestURL and port
     * from the original request will be used for getServerPort calls.
     *
     * @param serverPort server port
     */
    public void setServerPort(int serverPort) {
        this.enabled = true;
        this.serverPort = serverPort;
    }

    /**
     * Context path of the LB, must be starting with slash, e.g. /saml-extension
     *
     * @param contextPath context path
     */
    public void setContextPath(String contextPath) {
        this.enabled = true;
        this.contextPath = contextPath;
    }
}
