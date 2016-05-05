package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import java.util.Optional;
import java.util.Set;

/**
 * @author Ulises Bocchio
 */
public class ExtendedMetadataConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private ExtendedMetadata extendedMetadataBean;
    private ExtendedMetadata extendedMetadata;
    private ExtendedMetadata extendedMetadataConfig;

    private Boolean local;
    private Boolean idpDiscoveryEnabled;
    private Boolean ecpEnabled;
    private Boolean signMetadata;
    private Boolean requireLogoutRequestSigned;
    private Boolean requireLogoutResponseSigned;
    private Boolean requireArtifactResolveSigned;
    private Boolean supportUnsolicitedResponse;
    private String alias;
    private String idpDiscoveryURL;
    private String idpDiscoveryResponseURL;
    private String securityProfile;
    private String sslSecurityProfile;
    private String sslHostnameVerification;
    private String signingKey;
    private String signingAlgorithm;
    private String keyInfoGeneratorName;
    private String encryptionKey;
    private String tlsKey;
    private Set<String> trustedKeys;

    public ExtendedMetadataConfigurer() {

    }

    public ExtendedMetadataConfigurer(ExtendedMetadata extendedMetadata) {
        this.extendedMetadata = extendedMetadata;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        extendedMetadataBean = builder.getSharedObject(ExtendedMetadata.class);
        extendedMetadataConfig = builder.getSharedObject(SAMLSSOProperties.class).getExtendedMetadata();

    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (extendedMetadataBean == null) {
            if (extendedMetadata == null) {
                extendedMetadata = new ExtendedMetadata();
                extendedMetadata.setLocal(Optional.ofNullable(local).orElseGet(extendedMetadataConfig::isLocal));
                extendedMetadata.setIdpDiscoveryEnabled(Optional.ofNullable(idpDiscoveryEnabled).orElseGet(extendedMetadataConfig::isIdpDiscoveryEnabled));
                extendedMetadata.setEcpEnabled(Optional.ofNullable(ecpEnabled).orElseGet(extendedMetadataConfig::isEcpEnabled));
                extendedMetadata.setSignMetadata(Optional.ofNullable(signMetadata).orElseGet(extendedMetadataConfig::isSignMetadata));
                extendedMetadata.setRequireLogoutRequestSigned(Optional.ofNullable(requireLogoutRequestSigned).orElseGet(extendedMetadataConfig::isRequireLogoutRequestSigned));
                extendedMetadata.setRequireLogoutResponseSigned(Optional.ofNullable(requireLogoutResponseSigned).orElseGet(extendedMetadataConfig::isRequireLogoutResponseSigned));
                extendedMetadata.setRequireArtifactResolveSigned(Optional.ofNullable(requireArtifactResolveSigned).orElseGet(extendedMetadataConfig::isRequireArtifactResolveSigned));
                extendedMetadata.setSupportUnsolicitedResponse(Optional.ofNullable(supportUnsolicitedResponse).orElseGet(extendedMetadataConfig::isSupportUnsolicitedResponse));
                extendedMetadata.setAlias(Optional.ofNullable(alias).orElseGet(extendedMetadataConfig::getAlias));
                extendedMetadata.setIdpDiscoveryURL(Optional.ofNullable(idpDiscoveryURL).orElseGet(extendedMetadataConfig::getIdpDiscoveryURL));
                extendedMetadata.setIdpDiscoveryResponseURL(Optional.ofNullable(idpDiscoveryResponseURL).orElseGet(extendedMetadataConfig::getIdpDiscoveryResponseURL));
                extendedMetadata.setSecurityProfile(Optional.ofNullable(securityProfile).orElseGet(extendedMetadataConfig::getSecurityProfile));
                extendedMetadata.setSslSecurityProfile(Optional.ofNullable(sslSecurityProfile).orElseGet(extendedMetadataConfig::getSslSecurityProfile));
                extendedMetadata.setSslHostnameVerification(Optional.ofNullable(sslHostnameVerification).orElseGet(extendedMetadataConfig::getSslHostnameVerification));
                extendedMetadata.setSigningKey(Optional.ofNullable(signingKey).orElseGet(extendedMetadataConfig::getSigningKey));
                extendedMetadata.setSigningAlgorithm(Optional.ofNullable(signingAlgorithm).orElseGet(extendedMetadataConfig::getSigningAlgorithm));
                extendedMetadata.setKeyInfoGeneratorName(Optional.ofNullable(keyInfoGeneratorName).orElseGet(extendedMetadataConfig::getKeyInfoGeneratorName));
                extendedMetadata.setEncryptionKey(Optional.ofNullable(encryptionKey).orElseGet(extendedMetadataConfig::getEncryptionKey));
                extendedMetadata.setTlsKey(Optional.ofNullable(tlsKey).orElseGet(extendedMetadataConfig::getTlsKey));
                extendedMetadata.setTrustedKeys(Optional.ofNullable(trustedKeys).orElseGet(extendedMetadataConfig::getTrustedKeys));
            }
            builder.setSharedObject(ExtendedMetadata.class, extendedMetadata);
        }
    }

    public ExtendedMetadataConfigurer local(Boolean local) {
        this.local = local;
        return this;
    }

    public ExtendedMetadataConfigurer idpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
        this.idpDiscoveryEnabled = idpDiscoveryEnabled;
        return this;
    }

    public ExtendedMetadataConfigurer ecpEnabled(boolean ecpEnabled) {
        this.ecpEnabled = ecpEnabled;
        return this;
    }

    public ExtendedMetadataConfigurer signMetadata(boolean signMetadata) {
        this.signMetadata = signMetadata;
        return this;
    }

    public ExtendedMetadataConfigurer requireLogoutRequestSigned(boolean requireLogoutRequestSigned) {
        this.requireLogoutRequestSigned = requireLogoutRequestSigned;
        return this;
    }

    public ExtendedMetadataConfigurer requireLogoutResponseSigned(boolean requireLogoutResponseSigned) {
        this.requireLogoutResponseSigned = requireLogoutResponseSigned;
        return this;
    }

    public ExtendedMetadataConfigurer requireArtifactResolveSigned(boolean requireArtifactResolveSigned) {
        this.requireArtifactResolveSigned = requireArtifactResolveSigned;
        return this;
    }

    public ExtendedMetadataConfigurer supportUnsolicitedResponse(boolean supportUnsolicitedResponse) {
        this.supportUnsolicitedResponse = supportUnsolicitedResponse;
        return this;
    }

    public ExtendedMetadataConfigurer alias(String alias) {
        this.alias = alias;
        return this;
    }

    public ExtendedMetadataConfigurer idpDiscoveryURL(String idpDiscoveryURL) {
        this.idpDiscoveryURL = idpDiscoveryURL;
        return this;
    }

    public ExtendedMetadataConfigurer idpDiscoveryResponseURL(String idpDiscoveryResponseURL) {
        this.idpDiscoveryResponseURL = idpDiscoveryResponseURL;
        return this;
    }

    public ExtendedMetadataConfigurer securityProfile(String securityProfile) {
        this.securityProfile = securityProfile;
        return this;
    }

    public ExtendedMetadataConfigurer sslSecurityProfile(String sslSecurityProfile) {
        this.sslSecurityProfile = sslSecurityProfile;
        return this;
    }

    public ExtendedMetadataConfigurer sslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
        return this;
    }

    public ExtendedMetadataConfigurer signingKey(String signingKey) {
        this.signingKey = signingKey;
        return this;
    }

    public ExtendedMetadataConfigurer signingAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
        return this;
    }

    public ExtendedMetadataConfigurer keyInfoGeneratorName(String keyInfoGeneratorName) {
        this.keyInfoGeneratorName = keyInfoGeneratorName;
        return this;
    }

    public ExtendedMetadataConfigurer encryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
        return this;
    }

    public ExtendedMetadataConfigurer tlsKey(String tlsKey) {
        this.tlsKey = tlsKey;
        return this;
    }

    public ExtendedMetadataConfigurer trustedKeys(Set<String> trustedKeys) {
        this.trustedKeys = trustedKeys;
        return this;
    }
}
