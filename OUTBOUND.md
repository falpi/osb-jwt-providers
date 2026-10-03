<p align="center"><img src="doc/images/logo.png" /></p>
<div id="user-content-toc" align="center"><ul><summary><h1 align="center">Custom Outbound Authenticator<br/>OAUTH2 client credentials<br/>for OSB Business Services</h1></summary></ul></div>

<p align="center"><a href="README.md">README</a> · <a href="INBOUND.md">Inbound</a> · <b>Outbound</b> · <a href="doc/CustomAuthenticators-Guide.html">Guide</a> · <a href="doc/CustomAuthenticators-Issues.html">Issues</a></p>

## Overview
<p align="justify">The <code>CustomOutboundAuthenticator</code> (COA) secures the calls of OSB Business Services toward backends protected by OAUTH2. For each outgoing request the provider determines which identity the ESB must use toward that backend, obtains an access token from the IDP with the OAUTH2 client credentials flow, keeps it in cache and sets the <code>Authorization: Bearer</code> header on the request, together with optional custom headers and secret headers (e.g. Azure Function keys).<br/><br/>
Everything is declarative: the pipeline of the services does not contain any OAUTH2 logic, and a backend can be moved from one identity, resource, IDP or authentication method to another by changing the XML policies only. Two authentication methods are supported toward the IDP:</p>

- **secret**: the client secret of the identity is read from a mapping "Service Account" (`ClientSecrets`);
- **assertion**: a client assertion (JWT) is signed with the private key of the identity read from `ClientKeys.xml`, as recommended by Microsoft for production workloads.

<p align="center"><img src="doc/images/outbound-flow.svg" /></p>

## Installation notes
<p align="justify">The class is used in two roles. As a WebLogic security provider it is created in the realm (type <b>CustomOutboundAuthenticator</b>, e.g. named <code>CustomOAuth2Outbound</code>) and holds the MBean parameters and the caches; exactly one instance is allowed in the realm, a second one stops the server at boot. As an OSB outbound authentication class it is instantiated by OSB for each Business Service that references it; these instances borrow parameters and caches from the realm instance. The provider takes no part in user logins, so its position in the list of authentication providers and its control flag are not relevant.</p>

## How to configure Business Services
<p align="justify">To enable the provider on a Business Service, act from the JDeveloper IDE or from the Service Bus console on the transport details of the Business Service, as shown in the following screenshot: select "Custom Authentication" and type the class name <code>org.falpi.osb.security.providers.CustomOutboundAuthenticator</code> in the "HTTP Custom Authentication Class Name" field.<br/><br/>
Do not associate a "Service Account" with the Business Service: the provider rejects it. Retry count, retry interval and timeouts of the Business Service work as usual; please note that an error while obtaining the token is reported to OSB as a transport error and is therefore retried like a connection error.</p>

<p align="center"><img src="doc/images/business-service-transport.png" /></p>

## Provider Parameters
<p align="justify">Below is a detailed description of each parameter. The parameters shared with the inbound provider are described in more detail in the <a href="README.md#provider-parameters">README</a>.</p>

Parameter                     | Default   | Description
----------------------------- | --------- | ---------------------------------------------------------------
`PROVIDER_TYPE`               | OUTBOUND  | Fixed provider type.
`LOGGING_LINES`               | 10        | Maximum number of stacktrace lines logged.
`LOGGING_LEVEL`               | INFO      | Minimum level of log messages printed.
`LOGGING_INFO`                | (\*\*)    | Format of the logging line generated with the INFO level at the end of each request.
`THREADING_MODE`              | PARALLEL  | Multithreading strategy.
`REQUESTS_SSL_VERIFY`         | ENABLE    | SSL enforcement for the token requests. Use DISABLE only in non-production environments: with DISABLE secrets and assertions could be disclosed.
`REQUESTS_CONN_TIMEOUT`       | 5         | Connection timeout of the token requests (Seconds).
`REQUESTS_READ_TIMEOUT`       | 5         | Response timeout of the token requests (Seconds).
`REQUESTS_PROXY_MODE`         | DIRECT    | Proxy mediation for the token requests: DIRECT (no proxy), ANONYMOUS, BASIC, NTLM, KERBEROS (NEGOTIATE).
`REQUESTS_PROXY_PATH`         |           | OSB resource path (\*) of the "Proxy Server" used to extract proxy host and credentials.
`JWT_POLICIES_PATH`           |           | OSB resource path of the XML outbound policies. Mandatory. Template variables are not supported in this parameter.
`JWT_TEMPLATES_PATH`          |           | OSB resource path (\*) of the XML outbound templates. Mandatory.
`JWT_CLIENT_KEYS_PATH`        |           | OSB resource path (\*) of the XML client keys (assertion method). Mandatory.
`JWT_CLIENT_SECRETS_PATH`     |           | OSB resource path (\*) of the mapping "Service Account" with the client secrets (secret method). Mandatory.
`JWT_HEADER_SECRETS_PATH`     |           | OSB resource path (\*) of the mapping "Service Account" with the values of secure headers. Mandatory.
`JWT_RESOURCE_MAPPING_PATH`   |           | OSB resource path (\*) of the XML resource mappings. Mandatory.
`CUSTOM_REQUEST_HEADERS`      |           | Static headers added to every outbound request. Each line must follow the format \<header\>=\<value\>. Headers of the policies with the same name win.
`DEBUGGING_ASSERTION`         |           | May contain a javascript text that is used to filter log messages with TRACE or DEBUG level according to arbitrary criteria defined by the user. If present, it must return a Boolean object.
`DEBUGGING_PROPERTIES`        |           | Allows you to send one or more string expressions to the log file. They are printed as log messages with DEBUG level.
`KERBEROS_CONFIGURATION`      |           | Content of the krb5.conf file used for KERBEROS proxy authentication.
`ENCRYPTION_HELPER`           |           | Console helper to encrypt the passwords of the private keys (see "Client Keys"). Never used at runtime.

(\*) OSB resources path are constructed as follows: `<project-name>/<root-folder>/.../<parent-folder>/<resource-name>`. Template variables are allowed.<br/>
(\*\*) `Service: ${osb.service.name}, Identity: ${identity}`. Please note that `${identity}` is the logical identity; add `${client_id}` to log the GUID.<br/>

<p align="justify">Below is a screenshot of the available parameters populated with sample values.</p>

<p align="center"><img src="doc/images/outbound-parameters.png" /></p>

## Outbound Policies
<p align="justify">The XML resource referenced by <code>JWT_POLICIES_PATH</code> declares how each Business Service authenticates. It is validated against <code>OutboundPolicies.xsd</code>.</p>

```xml
<outboundPolicies xsi:noNamespaceSchemaLocation="../Schemas/OutboundPolicies.xsd" ...>

   <!-- SAMPLE: global defaults (every attribute is required here) -->
   <defaults provider="azure" identity="esb-default" method="assertion"
             scope="${resource}/.default" resource="api-${osb.project}" resource_mapped="true"
             secret_request="azure-token-v1" assertion_request="azure-token-v1" assertion_token="standard"
             token_cache_ttl="3000" token_cache_index="${token_url}:${identity}:${resource}:${scope}:${method}" />

   <!-- profiles: named sets of changes, referenced by projects or endpoints -->
   <profiles>
      <item name="secret-auth"   identity="esb-to-${osb.project}" method="secret" />
      <item name="function-keys" identity="esb-to-${osb.project}" method="secret"
            secureHeader="x-function-key:${osb.service.name}-${osb.operation}" />
   </profiles>

   <!-- changes for all the business services of an OSB project -->
   <projects>
      <item name="ProjectA" profile="function-keys" resource="function-a" />
      <item name="ProjectB" profile="secret-auth" />
   </projects>

   <!-- changes for a single business service -->
   <endpoints>
      <item name="BS_Orders_1.0" resource="function-b">
         <customHeader name="x-correlation-id" value="${uuid}" />
      </item>
      <item name="BS_BackendX_1.0" identity="esb-to-backend-x" method="assertion" resource="backend-x-api" />
      <item name="BS_Inventory_1.0" provider="keycloak" identity="esb-keycloak" method="assertion" assertion_request="keycloak"
            resource="" resource_mapped="false" />
   </endpoints>

</outboundPolicies>
```

<p align="justify">The names in the example are fictitious: provider and logical names are free text and only need to be consistent with ResourceMappings and the other resources (see the <a href="README.md#resource-mappings">README</a>). The complete file, together with all the resources it refers to, is in the sample project: <a href="osb/OAUTH2/Security/OutboundPolicies.xml"><code>osb/OAUTH2/Security/OutboundPolicies.xml</code></a>.</p>

#### Levels and precedence
<p align="justify">Four levels can define the same attributes. <code>defaults</code> must define all of them; <code>projects/item</code> applies to the Business Services of the OSB project with that name, <code>endpoints/item</code> to the Business Service with that name. A project or an endpoint may reference a profile, which is applied right after the level that references it (if the endpoint references a profile, the profile of the project is ignored). The most specific value wins.</p>

<p align="center"><img src="doc/images/outbound-policy-levels.svg" /></p>

#### Attributes
Attribute                                | Meaning
---------------------------------------- | ------------------------------------------------------------------------------------
`provider`                               | Logical name of the IDP. Qualifies identity and resource in ResourceMappings, ClientKeys and ClientSecrets.
`identity`                               | Logical name of the identity of the ESB toward the backend (templates allowed, e.g. `esb-to-${osb.project}`). Its value in ResourceMappings is the client_id.
`method`                                 | `secret` or `assertion`.
`resource`                               | Target resource (templates allowed). Translated through ResourceMappings when `resource_mapped` is `true`; an empty value is passed as is.
`resource_mapped`                        | `true` or `false`.
`scope`                                  | Scope of v2 token requests (templates allowed). Resolved after the resource, so `${resource}/.default` uses the translated value.
`secret_request`, `assertion_request`    | Name of the request template used for each method.
`assertion_token`                        | Name of the client assertion template.
`token_cache_ttl`                        | Seconds (0-3600) an access token is reused; it is never used beyond its own expiry. 0 disables the cache.
`token_cache_index`                      | Template of the cache key: it must contain everything that makes two tokens different.
`customHeader` / `<customHeader>`        | Header added to the request: inline as `name:value`, or as element with `name` and `value`. Values support templates.
`secureHeader` / `<secureHeader>`        | Header whose value is the password of the remote user named `key` (templates allowed) in HeaderSecrets: inline as `name:key`, or as element with `name` and `key`. A key such as `${osb.service.name}-${osb.operation}` selects a different value per service and operation (see [Client Secrets and Header Secrets](#client-secrets-and-header-secrets)).

<p align="justify">All the attributes become template variables (e.g. <code>${identity}</code>, <code>${resource}</code>) usable in the templates and in the other attributes.</p>

## Outbound Templates
<p align="justify">The XML resource referenced by <code>JWT_TEMPLATES_PATH</code> describes the token requests and the client assertions, so that any IDP supporting the client credentials flow can be used without code changes.</p>

```xml
<outboundTemplates xsi:noNamespaceSchemaLocation="../Schemas/OutboundTemplates.xsd" ...>
   <token name="standard" type="client_assertion">
      <claim name="iss" type="String">${client_id}</claim>
      <claim name="sub" type="String">${client_id}</claim>
      <claim name="aud" type="String">${token_url}</claim>
      <claim name="iat" type="Integer">${current.epoch}</claim>
      <claim name="exp" type="Integer">${current.epoch}+60</claim>
      <claim name="jti" type="String">${uuid}</claim>
   </token>
   <request name="azure-token-v1" method="secret" tokenURL="https://login.microsoftonline.com/<tenant>/oauth2/token">
      <parameter name="grant_type"    type="String">client_credentials</parameter>
      <parameter name="client_id"     type="String">${client_id}</parameter>
      <parameter name="client_secret" type="String">${client_secret}</parameter>
      <parameter name="resource"      type="String">${resource}</parameter>
   </request>
   <request name="azure-token-v2" method="assertion" tokenURL="https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token">
      <parameter name="grant_type"            type="String">client_credentials</parameter>
      <parameter name="client_id"             type="String">${client_id}</parameter>
      <parameter name="client_assertion_type" type="String">urn:ietf:params:oauth:client-assertion-type:jwt-bearer</parameter>
      <parameter name="client_assertion"      type="String">${client_assertion}</parameter>
      <parameter name="scope"                 type="String">${scope}</parameter>
   </request>
</outboundTemplates>
```

- A **request** (unique by `name` and `method`) defines the token endpoint (`tokenURL`, available as `${token_url}`) and the form parameters, sent with `POST` and `Content-Type: application/x-www-form-urlencoded`. The JSON response must contain `access_token`.
- A **token** (unique by `name` and `type`, type `client_assertion`) defines the claims of the client assertion, signed with the key of the identity (header `typ=JWT` and `kid` of the key).
- **Value types**: `String` values are taken literally after the resolution of the templates; `Integer` values are JavaScript expressions that must return an integer (e.g. `${current.epoch}+60`).

## Client Keys
<p align="justify">The XML resource referenced by <code>JWT_CLIENT_KEYS_PATH</code> contains the private keys used by the assertion method, one per IDP and identity. The public certificate must be registered on the IDP for the same client (in Entra ID: "Certificates &amp; secrets" of the app registration; the <code>kid</code> is the certificate thumbprint).</p>

```xml
<clientKeys xsi:noNamespaceSchemaLocation="../Schemas/ClientKeys.xsd" ...>
<item provider="azure" identity="esb-to-backend-x" kid="<certificate thumbprint>" alg="RS256"
      password="encrypted:<base64>">
-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----
</item>
</clientKeys>
```

- `provider` + `identity` identify the item; the client_id comes from ResourceMappings.
- Supported PEM formats: PKCS#8 (`BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`) and traditional OpenSSL (`BEGIN RSA PRIVATE KEY`, encrypted or not). Encrypted keys require `password`, plain keys require it empty.
- `password` can be written in clear or encrypted with the WebLogic domain key. To encrypt it, type the password in the `ENCRYPTION_HELPER` parameter of the provider, save, and copy the stored value (`encrypted:<base64>`) into the file. The value is valid only in the domain that encrypted it.

<p align="justify">Always use encrypted private keys and encrypted passwords: the file is an ordinary OSB resource, readable by anyone who can export the configuration.</p>

## Client Secrets and Header Secrets
<p align="justify">Secrets are kept in two OSB "Service Account" resources of type "mapping", used as secure key/value stores: only the "Remote Users" table is read, while the local user mappings can stay empty (an anonymous mapping avoids the editor complaint about an empty list).</p>

- **ClientSecrets**: remote user name `<provider>:<identity>`, remote password = `<client-secret>`. The name is the plain concatenation of provider name, colon and identity name, compared as a whole (e.g. provider `azure` and identity `esb-to-ProjectA` give `azure:esb-to-ProjectA`).
- **HeaderSecrets**: remote user name = the resolved `key` of a secure header, remote password = `<header-value>`. The key is a template, so a single policy can select a different secret for each service or operation: with `secureHeader="x-function-key:${osb.service.name}-${osb.operation}"` (the case of Azure Function Apps, where every function has its own key) a call to the operation `createOrder` of the Business Service `BS_Orders_1.0` reads the remote user `BS_Orders_1.0-createOrder`. Any template variable can be combined (project, service, operation, metadata, ...), and a fixed key works as well.

<p align="justify">Sample files: <a href="osb/OAUTH2/Security/OutboundTemplates.xml"><code>OutboundTemplates.xml</code></a>, <a href="osb/OAUTH2/Security/ClientKeys.xml"><code>ClientKeys.xml</code></a>, <a href="osb/OAUTH2/Security/ClientSecrets.sa"><code>ClientSecrets.sa</code></a> and <a href="osb/OAUTH2/Security/HeaderSecrets.sa"><code>HeaderSecrets.sa</code></a> in the sample project.</p>

<p align="center"><img src="doc/images/client-secrets-service-account.png" /><br/><i>ClientSecrets: one remote user per provider and identity.</i></p>

<p align="center"><img src="doc/images/header-secrets-service-account.png" /><br/><i>HeaderSecrets: one remote user per header key, here composed from service name and operation.</i></p>

<p align="justify">To rename remote users, edit the raw <code>.sa</code> file: the JDeveloper editor resets the passwords of renamed rows. A <code>.sa</code> file containing passwords encrypted for another domain makes the JDeveloper "Refresh Application" fail with "Invalid padding". Do not keep real secrets in the project sources: set them per environment.</p>

## Processing flow
1. **Context**: checks that the realm provider exists and that the Business Service has no Service Account, and detects the OSB operation.
2. **Policies**: selects the levels that apply to the Business Service and consolidates attributes and headers.
3. **Templates and mappings**: selects the request template of the method (and the token template for assertion), loads ResourceMappings.
4. **Authentication**: translates the identity into `${client_id}`; reads `${client_secret}` from ClientSecrets or signs `${client_assertion}` with the key from ClientKeys.
5. **Authorization**: resolves and translates the resource, then resolves the scope.
6. **Access token**: computes the cache key; on a cache miss sends the token request and caches the token.
7. **Headers**: sets `Authorization: Bearer <token>`, the MBean custom headers and the policy headers (secure values read from HeaderSecrets).
8. **Logging**: debugging properties and INFO line; OSB then sends the request.

#### Operation detection
<p align="justify">The variable <code>${osb.operation}</code>, typically used in the keys of secure headers, is taken from the message context of the pipeline (<code>$outbound</code> operation, then <code>$operation</code>). When there is no pipeline (Business Service tested from the OSB console) or the context has no operation, for SOAP services the operation is looked up in the WSDL by SOAPAction, or taken as the only operation of the binding. Otherwise it is empty. <code>${osb.operation.source}</code> and <code>${osb.operation.message}</code> tell which rule applied.</p>

#### Faults
<p align="justify">Errors are returned to OSB as transport errors with a short message; the detail is written in the provider log. When the IDP answers with an error, its <code>error_description</code> is appended to the message, for example:</p>

```
OSB-380000: General runtime error: Error while preparing access token (AADSTS7000215: Invalid client secret provided. ...)
```

Message                                                     | Cause
----------------------------------------------------------- | ------------------------------------------------------------------
Custom Outbound provider not configured in security realm   | No outbound provider in the realm.
Service Account not allowed (service)                       | The Business Service has a Service Account.
Configuration error                                         | Empty mandatory parameter.
Error while parsing security policies                       | Policies not loadable, defaults or profile missing.
Error in security policies custom headers (...)             | Malformed header definition.
Error while parsing templates                               | Templates not loadable or template not found for the method.
Error while parsing resource mappings                       | ResourceMappings not loadable.
Identity mapping error (provider:identity)                  | Identity not mapped, secret not found, client key not found or not usable.
Resource error (resource) / Scope error (scope)             | Template or mapping error.
Error while preparing access token [(error_description)]    | Token request failed or response without access_token.
Secure header error ('name')                                | HeaderSecrets not readable or key not found.

## Template Variables
<p align="justify">In addition to the common variables listed in the <a href="README.md#template-variables">README</a>, the following variables are available in the outbound provider.</p>

Variable                                   | Replaced by
------------------------------------------ | ------------------------------------------------------------------------------------
`${osb.operation}`                         | Operation of the Business Service being invoked (see "Operation detection").
`${osb.operation.source}`, `${osb.operation.message}` | How the operation was detected.
`${provider}`, `${identity}`, `${method}`, `${resource}`, `${resource_mapped}`, `${scope}`, `${secret_request}`, `${assertion_request}`, `${assertion_token}`, `${token_cache_ttl}`, `${token_cache_index}` | Consolidated policy attributes (resource and scope after resolution).
`${token_url}`                             | Token endpoint of the selected request template.
`${client_id}`                             | Client id of the identity.
`${client_secret}`, `${client_assertion}`  | Credential of the selected method (use them only in request templates).
`${http.header.<name>}`, `${http.header.*}`| Headers of the outbound request built by the pipeline.
`${http.content.body}`                     | Outbound payload.
`${osb.metadata.<name>}`, `${osb.metadata.*}` | User metadata of the outbound request.
`${osb.context.<variable>}`, `${osb.context.*}` | Pipeline context variables (empty when there is no pipeline).
`${username}`                              | User of the inbound security context (pipeline calls only).

## Log Management
<p align="justify">Below is an example of the logs generated by an outbound request with the DEBUG level (abridged).</p>

```log
... <DEBUG> ##########################################################################################
... <DEBUG> OUTBOUND AUTH
... <DEBUG> ##########################################################################################
... <DEBUG> ==========================================================================================
... <DEBUG> CONFIGURATION
... <DEBUG> ==========================================================================================
... <DEBUG> PROVIDER_TYPE ................: OUTBOUND
... <DEBUG> LOGGING_LEVEL ................: DEBUG
... <DEBUG> JWT_POLICIES_PATH ............: OAUTH2/Security/OutboundPolicies
... <DEBUG> JWT_TEMPLATES_PATH ...........: OAUTH2/Security/OutboundTemplates
... <DEBUG> JWT_CLIENT_KEYS_PATH .........: OAUTH2/Security/ClientKeys
... <DEBUG> JWT_CLIENT_SECRETS_PATH ......: OAUTH2/Security/ClientSecrets
... <DEBUG> JWT_HEADER_SECRETS_PATH ......: OAUTH2/Security/HeaderSecrets
... <DEBUG> JWT_RESOURCE_MAPPING_PATH ....: OAUTH2/Security/ResourceMappings
... <DEBUG> ==========================================================================================
... <DEBUG> CONTEXT
... <DEBUG> ==========================================================================================
... <DEBUG> Managed Name .................: DefaultServer
... <DEBUG> Project Name .................: ProjectA
... <DEBUG> Service Name .................: BS_Orders_1.0
... <DEBUG> Operation Name ...............: createOrder
... <DEBUG> Operation Source .............: message context ($outbound)
... <DEBUG> Operation Message ............: 
... <DEBUG> ------------------------------------------------------------------------------------------
... <DEBUG> Policy Attribute .............: provider => azure
... <DEBUG> Policy Attribute .............: identity => esb-to-${osb.project}
... <DEBUG> Policy Attribute .............: method => secret
... <DEBUG> Policy Attribute .............: resource => function-b
... <DEBUG> Policy Custom Header .........: (secure) x-function-key => ${osb.service.name}-${osb.operation}
... <DEBUG> Templates Path ...............: OAUTH2/Security/OutboundTemplates
... <DEBUG> Resource Mapping Path ........: OAUTH2/Security/ResourceMappings
... <DEBUG> ==========================================================================================
... <DEBUG> JWT AUTH
... <DEBUG> ==========================================================================================
... <DEBUG> Client ID ....................: <client_id>
... <DEBUG> Client Secret Path ...........: OAUTH2/Security/ClientSecrets
... <DEBUG> ------------------------------------------------------------------------------------------
... <DEBUG> ACCESS TOKEN REQUEST
... <DEBUG> ------------------------------------------------------------------------------------------
... <DEBUG> ==========================================================================================
... <DEBUG> CUSTOM HEADERS
... <DEBUG> ==========================================================================================
... <DEBUG> Header Secrets Path ..........: OAUTH2/Security/HeaderSecrets
... <DEBUG> ##########################################################################################
... <INFO>  Outbound (JWT) => Service: BS_Orders_1.0, Identity: esb-to-ProjectA
```

<p align="justify">At DEBUG level the values of the headers added to the request are logged too (including the translated secure headers), and at TRACE level the token request and response, which contain client secrets or client assertions and access tokens. Do not keep these levels active in production, or restrict them with DEBUGGING_ASSERTION.</p>

## Tips
- Use a `token_cache_ttl` a few minutes shorter than the token lifetime (e.g. 3000 seconds for one-hour tokens) and never 0 in production: every call would request a new token.
- Prefer the `assertion` method with an encrypted key over client secrets.
- Use HTTPS for every token endpoint.
- Keep in `token_cache_index` every variable that changes the token (URL, identity, resource, scope, method), otherwise a token could be reused for the wrong backend.
