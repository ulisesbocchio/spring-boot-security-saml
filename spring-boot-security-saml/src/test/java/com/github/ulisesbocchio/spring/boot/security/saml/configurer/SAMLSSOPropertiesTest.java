package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Ulises Bocchio
 */
@RunWith(SpringJUnit4ClassRunner.class)
@TestPropertySource("classpath:test.properties")
@SpringBootTest(classes = SAMLSSOPropertiesTest.TestConfig.class)
public class SAMLSSOPropertiesTest {

    @EnableConfigurationProperties(SAMLSSOProperties.class)
    @Configuration
    static class TestConfig {

    }

    @Autowired
    private SAMLSSOProperties config;

    @Test
    public void contextLoads() {
        assertThat(config).isNotNull();
        assertThat(config.getDefaultFailureUrl()).isEqualTo("/error/test");
        assertThat(config.getDefaultSuccessUrl()).isEqualTo("/success/test");
        assertThat(config.getDiscoveryProcessingUrl()).isEqualTo("/discovery/test");
        assertThat(config.isEnableSsoHok()).isEqualTo(false);
        assertThat(config.getIdpSelectionPageUrl()).isEqualTo("/idpselection/test");
        assertThat(config.getSsoHokProcessingUrl()).isEqualTo("/hok/test");
        assertThat(config.getSsoLoginUrl()).isEqualTo("/login/test");
        assertThat(config.getSsoProcessingUrl()).isEqualTo("/sso/test");

        assertThat(config.getAuthenticationProvider().isExcludeCredential()).isEqualTo(true);
        assertThat(config.getAuthenticationProvider().isForcePrincipalAsString()).isEqualTo(true);

        assertThat(config.getExtendedDelegate().isForceMetadataRevocationCheck()).isEqualTo(true);
        assertThat(config.getExtendedDelegate().isMetadataRequireSignature()).isEqualTo(true);
        assertThat(config.getExtendedDelegate().isMetadataTrustCheck()).isEqualTo(true);
        assertThat(config.getExtendedDelegate().getMetadataTrustedKeys()).containsExactly("foo", "bar");
        assertThat(config.getExtendedDelegate().isRequireValidMetadata()).isEqualTo(true);

        assertThat(config.getExtendedMetadata().getAlias()).isEqualTo("alias");
        assertThat(config.getExtendedMetadata().isEcpEnabled()).isEqualTo(true);
        assertThat(config.getExtendedMetadata().getEncryptionKey()).isEqualTo("enckey");
        assertThat(config.getExtendedMetadata().isIdpDiscoveryEnabled()).isEqualTo(true);
        assertThat(config.getExtendedMetadata().getIdpDiscoveryResponseUrl()).isEqualTo("/discovery/response");
        assertThat(config.getExtendedMetadata().getIdpDiscoveryUrl()).isEqualTo("/discovery/idp");
        assertThat(config.getExtendedMetadata().getKeyInfoGeneratorName()).isEqualTo("generator");
        assertThat(config.getExtendedMetadata().isLocal()).isEqualTo(true);
        assertThat(config.getExtendedMetadata().isRequireArtifactResolveSigned()).isEqualTo(false);
        assertThat(config.getExtendedMetadata().isRequireLogoutRequestSigned()).isEqualTo(false);
        assertThat(config.getExtendedMetadata().isRequireLogoutResponseSigned()).isEqualTo(true);
        assertThat(config.getExtendedMetadata().getSecurityProfile()).isEqualTo("profile");
        assertThat(config.getExtendedMetadata().isSignMetadata()).isEqualTo(true);
        assertThat(config.getExtendedMetadata().getSigningAlgorithm()).isEqualTo("algorithm");
        assertThat(config.getExtendedMetadata().getSigningKey()).isEqualTo("signing");
        assertThat(config.getExtendedMetadata().getSslHostnameVerification()).isEqualTo("verification");
        assertThat(config.getExtendedMetadata().getSslSecurityProfile()).isEqualTo("sslprofile");
        assertThat(config.getExtendedMetadata().isSupportUnsolicitedResponse()).isEqualTo(false);
        assertThat(config.getExtendedMetadata().getTlsKey()).isEqualTo("tlskey");

        assertThat(config.getIdp().getMetadataLocation()).isEqualTo("metadatalocation");

        assertThat(config.getKeyManager().getDefaultKey()).isEqualTo("defaultkey");
        assertThat(config.getKeyManager().getKeyPasswords()).containsOnlyKeys("foo", "localhost").containsValues("bar", "");
        assertThat(config.getKeyManager().getPrivateKeyDerLocation()).isEqualTo("der");
        assertThat(config.getKeyManager().getPublicKeyPemLocation()).isEqualTo("pem");
        assertThat(config.getKeyManager().getStoreLocation()).isEqualTo("storelocation");
        assertThat(config.getKeyManager().getStorePass()).isEqualTo("storepass");

        assertThat(config.getLogout().isClearAuthentication()).isEqualTo(false);
        assertThat(config.getLogout().getDefaultTargetUrl()).isEqualTo("/target");
        assertThat(config.getLogout().isInvalidateSession()).isEqualTo(true);
        assertThat(config.getLogout().getLogoutUrl()).isEqualTo("/saml/logout/test");
        assertThat(config.getLogout().getSingleLogoutUrl()).isEqualTo("/saml/SingleLogout/test");

        assertThat(config.getMetadataGenerator().getAssertionConsumerIndex()).isEqualTo(1);
        assertThat(config.getMetadataGenerator().getBindingsHokSso()).containsExactly("a", "b", "c");
        assertThat(config.getMetadataGenerator().getBindingsSlo()).containsExactly("x", "y", "z");
        assertThat(config.getMetadataGenerator().getBindingsSso()).containsExactly("one", "two", "three");
        assertThat(config.getMetadataGenerator().getEntityBaseUrl()).isEqualTo("/base");
        assertThat(config.getMetadataGenerator().getEntityId()).isEqualTo("entityid");
        assertThat(config.getMetadataGenerator().getId()).isEqualTo("generator");
        assertThat(config.getMetadataGenerator().isIncludeDiscoveryExtension()).isEqualTo(false);
        assertThat(config.getMetadataGenerator().getMetadataUrl()).isEqualTo("/saml/metadata/test");
        assertThat(config.getMetadataGenerator().getNameId()).containsExactly("nameid");
        assertThat(config.getMetadataGenerator().isRequestSigned()).isEqualTo(false);
        assertThat(config.getMetadataGenerator().isWantAssertionSigned()).isEqualTo(false);

        assertThat(config.getMetadataManager().getDefaultIdp()).isEqualTo("defaultidp");
        assertThat(config.getMetadataManager().getHostedSpName()).isEqualTo("spname");
        assertThat(config.getMetadataManager().getRefreshCheckInterval()).isEqualTo(666);

        assertThat(config.getProfileOptions().getAllowCreate()).isEqualTo(false);
        assertThat(config.getProfileOptions().getAllowedIdps()).containsExactly("one", "two");
        assertThat(config.getProfileOptions().getAssertionConsumerIndex()).isEqualTo(666);
        assertThat(config.getProfileOptions().getAuthnContextComparison()).isEqualTo(AuthnContextComparisonTypeEnumeration.MINIMUM);
        assertThat(config.getProfileOptions().getAuthnContexts()).containsExactly("three", "four");
        assertThat(config.getProfileOptions().getBinding()).isEqualTo("binding");
        assertThat(config.getProfileOptions().getForceAuthn()).isEqualTo(true);
        assertThat(config.getProfileOptions().getIncludeScoping()).isEqualTo(false);
        assertThat(config.getProfileOptions().getNameId()).isEqualTo("nameid");
        assertThat(config.getProfileOptions().getPassive()).isEqualTo(true);
        assertThat(config.getProfileOptions().getProviderName()).isEqualTo("provider");
        assertThat(config.getProfileOptions().getProxyCount()).isEqualTo(555);
        assertThat(config.getProfileOptions().getRelayState()).isEqualTo("relaystate");

        assertThat(config.getSamlProcessor().isArtifact()).isEqualTo(false);
        assertThat(config.getSamlProcessor().isPaos()).isEqualTo(false);
        assertThat(config.getSamlProcessor().isPost()).isEqualTo(false);
        assertThat(config.getSamlProcessor().isRedirect()).isEqualTo(false);
        assertThat(config.getSamlProcessor().isSoap()).isEqualTo(false);

        assertThat(config.getTls().getProtocolName()).isEqualTo("http");
        assertThat(config.getTls().getProtocolPort()).isEqualTo(4433);
        assertThat(config.getTls().getSslHostnameVerification()).isEqualTo("none");
        assertThat(config.getTls().getTrustedKeys()).containsExactly("one", "two");
    }
}
