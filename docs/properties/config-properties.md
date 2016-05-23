### Configuration Properties

Configuring your Service Provider through configuration properties is pretty straight forward and most configurations could be accomplished this way. The two limitations that exists are: You can only configure what is exposed as properties, obviously, and you cannot provide specific implementations or instances of the different Spring Security SAML classes/interfaces. If you need to provide custom implementations of certain types or a more dynamic configuration you'll need to use the [Java DSL](#java-dsl) approach for that configuration, but as expressed before, you can configure as much as you can through properties, while using the DSL configuration for any dynamic or custom implementations configuration. You can mix the two flavors.   
The following table shows all the available properties (Parsed from Spring Configuration Metadata file).

|Key	|Default Value	|Description	|
|----------------------------------------------------------	|---	|---	|
|saml.sso.default-failure-url	|/error	|The URL which will be used as the failure destination.	|
|saml.sso.default-success-url	|/	|Supplies the default target Url that will be used if no saved request is found in the session, or the  alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative to  the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name (such as  "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also supported.	|
|saml.sso.discovery-processing-url	|/saml/discovery	|The URL that the {@link SAMLDiscovery} filter will be listening to.	|
|saml.sso.enable-sso-hok	|true	|Whether to enable the {@link SAMLWebSSOHoKProcessingFilter} filter or not.	|
|saml.sso.idp-selection-page-url	|/idpselection	|Sets path where request dispatcher will send user for IDP selection. In case it is null the default IDP will  always be used.	|
|saml.sso.sso-hok-processing-url	|/saml/HoKSSO	|The URL that the {@link SAMLWebSSOHoKProcessingFilter} will be listening to. Only relevant if {@code  enableSsoHok} is true.	|
|saml.sso.sso-login-url	|saml/login	|The URL that the {@link SAMLEntryPoint} filter will be listening to.	|
|saml.sso.sso-processing-url	|/saml/SSO	|The URL that the {@link SAMLProcessingFilter} will be listening to.	|
|saml.sso.authentication-provider.exclude-credential	|false	|By default principal in the returned Authentication object is the NameID included in the authenticated  Assertion. The NameID is not serializable. Setting this value to true will force the NameID value to be a  String.	|
|saml.sso.authentication-provider.force-principal-as-string	|false	|When false (default) the resulting Authentication object will include instance of SAMLCredential as a  credential value. The credential includes information related to the authentication process, received  attributes and is required for Single Logout. In case your application doesn't require the credential, it is  possible to exclude it from the Authentication object by setting this flag to true.	|
|saml.sso.extended-delegate.force-metadata-revocation-check	|false	|Determines whether check for certificate revocation should always be done as part of the PKIX validation.  Revocation is evaluated by the underlaying JCE implementation and depending on configuration may include CRL  and OCSP verification of the certificate in question. When set to false revocation is only performed when  MetadataManager includes CRLs.	|
|saml.sso.extended-delegate.metadata-require-signature	|false	|When set to true metadata from this provider should only be accepted when correctly signed and verified.  Metadata with an invalid signature or signed by a not-trusted credential will be ignored.	|
|saml.sso.extended-delegate.metadata-trust-check	|false	|When true metadata signature will be verified for trust using PKIX with metadataTrustedKeys  as anchors.	|
|saml.sso.extended-delegate.metadata-trusted-keys	|null	|Keys stored in the KeyManager which can be used to verify whether signature of the metadata is trusted.  If not set any key stored in the keyManager is considered as trusted.	|
|saml.sso.extended-delegate.require-valid-metadata	|false	|Sets whether the metadata returned by queries must be valid.	|
|saml.sso.extended-metadata.alias	|null	|Local alias of the entity used for construction of well-known metadata address and determining target  entity from incoming requests.	|
|saml.sso.extended-metadata.ecp-enabled	|false	|Indicates whether Enhanced Client/Proxy profile should be used for requests which support it. Only valid for  local entities.	|
|saml.sso.extended-metadata.encryption-key	|null	|Key (stored in the local keystore) used for encryption/decryption of messages coming/sent from this entity. For  local entities  private key must be available, for remote entities only public key is required.	|
|saml.sso.extended-metadata.idp-discovery-enabled	|false	|When true IDP discovery will be invoked before SSO. Only valid for local entities.	|
|saml.sso.extended-metadata.idp-discovery-response-url	|null	|URL where the discovery service should send back response to our discovery request. Only valid for local  entities.	|
|saml.sso.extended-metadata.idp-discovery-url	|null	|URL of the IDP Discovery service user should be redirected to upon request to determine which IDP to use.  Value can override settings in the local SP metadata. Only valid for local entities.	|
|saml.sso.extended-metadata.key-info-generator-name	|null	|Name of generator for KeyInfo elements in metadata and signatures. At the moment only used for metadata  signatures.  Only valid for local entities.	|
|saml.sso.extended-metadata.local	|false	|Setting of the value determines whether the entity is deployed locally (hosted on the current installation) or  whether it's an entity deployed elsewhere.	|
|saml.sso.extended-metadata.require-artifact-resolve-signed	|true	|If true received artifactResolve messages will require a signature, sent artifactResolve will be signed.	|
|saml.sso.extended-metadata.require-logout-request-signed	|true	|SAML specification mandates that incoming LogoutRequests must be authenticated.	|
|saml.sso.extended-metadata.require-logout-response-signed	|false	|Flag indicating whether incoming LogoutResposne messages must be authenticated.	|
|saml.sso.extended-metadata.security-profile	|metaiop	|Profile used for trust verification, MetaIOP by default. Only relevant for local entities.	|
|saml.sso.extended-metadata.sign-metadata	|false	|Flag indicating whether to sign metadata for this entity. Only valid for local entities.	|
|saml.sso.extended-metadata.signing-algorithm	|null	|Algorithm used for creation of digital signatures of this entity. At the moment only used for metadata  signatures.  Only valid for local entities.	|
|saml.sso.extended-metadata.signing-key	|null	|Key (stored in the local keystore) used for signing/verifying signature of messages sent/coming from this  entity. For local entities private key must be available, for remote entities only public key is required.	|
|saml.sso.extended-metadata.ssl-hostname-verification	|default	|Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.	|
|saml.sso.extended-metadata.ssl-security-profile	|pkix	|Profile used for SSL/TLS trust verification, PKIX by default. Only relevant for local entities.	|
|saml.sso.extended-metadata.support-unsolicited-response	|true	|Flag indicating whether to support unsolicited responses (IDP-initialized SSO). Only valid for remote  entities.	|
|saml.sso.extended-metadata.tls-key	|null	|Key used for verification of SSL/TLS connections. For local entities key is included in the generated metadata  when specified.  For remote entities key is used to for server authentication of SSL/TLS when specified and when MetaIOP security  profile is used.	|
|saml.sso.extended-metadata.trusted-keys	|null	|Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is  null  all keys in the keyStore will be treated as trusted.	|
|saml.sso.idps.metadata-location	|classpath:idp-metadata.xml	|Specify the location(s) of the metadata files to be loaded as {@link ResourceBackedMetadataProvider}	|
|saml.sso.key-manager.default-key	|localhost	|The default key name to use for encryption.	|
|saml.sso.key-manager.key-passwords	|null	|They KeyStore private key passwords by key name.	|
|saml.sso.key-manager.private-key-der-location	|null	|Specify a DER private key location. Used in conjunction with publicKeyPemLocation.	|
|saml.sso.key-manager.public-key-pem-location	|null	|Specify a PEM certificate location. Used in conjunction with privateKeyDerLocation.	|
|saml.sso.key-manager.store-location	|null	|The location of KeyStore resource. If used, privateKeyDerLocation and privateKeyDerLocation are ignored.	|
|saml.sso.key-manager.store-pass	|null	|The KeyStore password. Not relevant when using privateKeyDerLocation and privateKeyDerLocation.	|
|saml.sso.logout.clear-authentication	|true	|If true, removes the Authentication from the SecurityContext to prevent issues with concurrent requests.	|
|saml.sso.logout.default-target-url	|/	|Supplies the default target Url that will be used if no saved request is found in the session, or the  alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative  to the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name  (such as "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also  supported.	|
|saml.sso.logout.invalidate-session	|false	|Causes the HttpSession to be invalidated when this LogoutHandler is invoked. Defaults to true.	|
|saml.sso.logout.logout-url	|/saml/logout	|Sets the URL used to determine if the {@link SAMLLogoutFilter} is invoked.	|
|saml.sso.logout.single-logout-url	|saml/SingleLogout	|Sets the URL used to determine if the {@link SAMLLogoutProcessingFilter} is invoked.	|
|saml.sso.metadata-generator.assertion-consumer-index	|0	|Generated assertion consumer service with the index equaling set value will be marked as default. Use  negative value to skip the default attribute altogether.	|
|saml.sso.metadata-generator.bindings-hok-sso	|null	|List of bindings to be included in the generated metadata for Web Single Sign-On Holder of Key. Ordering of  bindings affects inclusion in the generated metadata. Supported values are: "artifact" (or  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") and "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").  By default there are no included bindings for the profile.	|
|saml.sso.metadata-generator.bindings-slo	|null	|List of bindings to be included in the generated metadata for Single Logout. Ordering of bindings affects  inclusion in the generated metadata. Supported values are: "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")  and "redirect" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"). The following bindings are  included  by default: "post", "redirect".	|
|saml.sso.metadata-generator.bindings-sso	|null	|List of bindings to be included in the generated metadata for Web Single Sign-On. Ordering of bindings  affects inclusion in the generated metadata. Supported values are: "artifact" (or  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"), "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")  and "paos" (or "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"). The following bindings are included by default:  "artifact", "post".	|
|saml.sso.metadata-generator.entity-base-url	|null	|This Service Provider's entity base URL. Provide if base URL cannot be inferred by using the hostname where  the Service Provider will be running. I.E. if running on the cloud behind a load balancer.	|
|saml.sso.metadata-generator.entity-id	|localhost	|This Service Provider's SAML Entity ID. Used as entity id for generated requests from this Service Provider.	|
|saml.sso.metadata-generator.id	|null	|Local ID. Used as part of Entity Descriptor.	|
|saml.sso.metadata-generator.include-discovery-extension	|true	|When true discovery profile extension metadata pointing to the default SAMLEntryPoint will be generated and  stored in the generated metadata document.	|
|saml.sso.metadata-generator.metadata-url	|/saml/metadata	|{@link MetadataDisplayFilter} processing URL. Defines which URL will display the Service Provider Metadata.	|
|saml.sso.metadata-generator.name-id	|null	|NameIDs to be included in generated metadata.	|
|saml.sso.metadata-generator.request-signed	|true	|Whether Authentication Requests should be signed by this Service Provider or not.	|
|saml.sso.metadata-generator.want-assertion-signed	|true	|Whether incoming SAML assertions should be signed or not.	|
|saml.sso.metadata-manager.default-idp	|null	|Sets name of IDP to be used as default.	|
|saml.sso.metadata-manager.hosted-sp-name	|null	|Sets nameID of SP hosted on this machine. This can either be called from springContext or automatically  during invocation of metadata generation filter.	|
|saml.sso.metadata-manager.refresh-check-interval	|-1	|Interval in milliseconds used for re-verification of metadata and their reload. Upon trigger each provider  is asked to return it's metadata, which might trigger their reloading. In case metadata is reloaded the  manager is notified and automatically refreshes all internal data by calling refreshMetadata.  <p>  In case the value is smaller than zero the timer is not created.  </p>	|
|saml.sso.profile-options.allow-create	|null	|Flag indicating whether IDP can create new user based on the current authentication request. Null value will  omit field from the request.	|
|saml.sso.profile-options.allowed-idps	|null	|List of IDPs which are allowed to process the created AuthnRequest. IDP the request will be sent to is added  automatically. In case value is null the allowedIDPs will not be included in the Scoping element.  <p>  Property includeScoping must be enabled for this value to take any effect.  </p>	|
|saml.sso.profile-options.assertion-consumer-index	|null	|When set determines assertionConsumerService and binding to which should IDP send response. By default  service is determined automatically. Available indexes can be found in metadata of this service provider.	|
|saml.sso.profile-options.authn-context-comparison	|null	|Comparison to use for WebSSO requests. No change for null values.	|
|saml.sso.profile-options.authn-contexts	|null	|Enable different {@link org.opensaml.saml2.core.AuthnContext} to be sent and validated based on {@code authnContextComparison}.	|
|saml.sso.profile-options.binding	|null	|Binding to be used for for sending SAML message to IDP.	|
|saml.sso.profile-options.force-authn	|false	|Whether to always force Authentication when redirected to the IDP or to allow IDP-managed sessions (basically disables Single Sign On for the local entity).	|
|saml.sso.profile-options.include-scoping	|true	|True if scoping element should be included in the requests sent to IDP.	|
|saml.sso.profile-options.name-id	|null	|NameID to used or null to omit NameIDPolicy from request.	|
|saml.sso.profile-options.passive	|false	|Whether the IdP should refrain from interacting with the user during the authentication process. Boolean  values will be marshalled to either "true" or "false".	|
|saml.sso.profile-options.provider-name	|null	|Human readable name of the local entity.	|
|saml.sso.profile-options.proxy-count	|2	|Null to skip proxyCount, 0 to disable proxying, &gt;0 to allow proxying	|
|saml.sso.profile-options.relay-state	|null	|Relay state sent to the IDP as part of the authentication request. Value will be returned by IDP and made available  in the SAMLCredential after successful authentication.	|
|saml.sso.saml-processor.artifact	|true	|Disable/Enable HTTP Artifact Bindings.	|
|saml.sso.saml-processor.paos	|true	|Disable/Enable PAOS Bindings.	|
|saml.sso.saml-processor.post	|true	|Disable/Enable HTTP POST Bindings.	|
|saml.sso.saml-processor.redirect	|true	|Disable/Enable HTTP Redirect Bindings.	|
|saml.sso.saml-processor.soap	|true	|Disable/Enable SOAP Bindings.	|
|saml.sso.tls.protocol-name	|https	|Name of protocol to register.	|
|saml.sso.tls.protocol-port	|443	|Default port of protocol.	|
|saml.sso.tls.ssl-hostname-verification	|default	|Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.	|
|saml.sso.tls.trusted-keys	|null	|Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is  null all keys in the keyStore will be treated as trusted.	|
