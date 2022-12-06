# secure-api-gateway-ig-extensions
This is an extension module for IG, it contains Filters and helper classes which can be called from Filters to handle
common tasks which are required to build a secure API gateway.

To install this module the jar needs to be placed into [config/7.1.0/securebanking/ig/lib](../config/7.1.0/securebanking/ig/lib).

# JWKS Caching Support
Support for fetching (and optionally caching) JSON Web Key Set (JWKS) data.

## Key classes
The JwkSetService interface is used to control the behaviour when fetching JWKS, the default implementation: [RestJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/RestJwkSetService.java) will always fetch data using a HTTP call to a REST API.

The [CachingJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/cache/CachingJwkSetService.java) provides caching support via a pluggable Cache interface. The service will first check its cache and return the cached JWKS if there is one, otherwise it will delegate to the RestJwkSetService to get the data and cache it.

[CaffeineCachingJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/cache/caffeine/CaffeineCachingJwkSetService.java) provides a concrete implementation which uses the [caffeine](https://github.com/ben-manes/caffeine) library (this lib is already used within IG).

## IG heap configuration
Caching behaviour can be controlled via IG config.

A heap object with name: `OBJwkSetService` of type `com.forgerock.sapi.gateway.jwks.JwkSetService` is a dependency of routes which need to fetch JWKS data.

The following snippets can be placed into the heap section of [config.json](../config/7.1.0/securebanking/ig/config/prod/config/config.json) to control which JwkSetService implementation is used.

### Enable caching
```
{
      "name": "OBJwkSetService",
      "type": "CaffeineCachingJwkSetService",
      "config": {
        "maxCacheEntries": 500,
        "expireAfterWriteDuration": "12 hours"
      }
}
```

| config option            | description                                                                                                                                                            | default                                                |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| maxCacheEntries          | The maximum number of values that can be stored in the cache                                                                                                           | 100                                                    |
| expireAfterWriteDuration | Values will be removed from the cache when this time elapses after the value was last written.<br/>This is a String representation of org.forgerock.util.time.Duration | "5 minutes"                                            |
| handler                  | The org.forgerock.openig.handler.ClientHandler instance to use to send the HTTP requests to fetch the JWKS data                                                        | "ClientHandler", which is the default IG ClientHandler |

### No Caching
```
{
      "name": "OBJwkSetService",
      "type": "RestJwkSetService"
}
```

| config option | description                                                                                                                                        | default                                             |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| handler       | The org.forgerock.openig.handler.ClientHandler instance to use to send the HTTP requests to fetch the JWKS data                                    | "ClientHandler", which is the default ClientHandler |

### Route configuration
The [ProcessDetachedSig](../config/7.1.0/securebanking/ig/scripts/groovy/ProcessDetachedSig.groovy) filter has a dependency on a JwkSetService object in order to get JWKS data to verify the `x-jws-signature` header sent in OBIE API requests. 

Routes which use the ProcessDetachedSig filter must ensure that they configure the filter arg: `"jwkSetService": "${heap['OBJwkSetService']}"`

## Extensions
Clients can use an alternative caching library by writing an adaptor class which implements the [com.forgerock.sapi.gateway.jwks.cache.Cache](src/main/java/com/forgerock/sapi/gateway/jwks/cache/Cache.java) interface. 

The contents of package [com.forgerock.sapi.gateway.jwks.cache.caffeine](src/main/java/com/forgerock/sapi/gateway/jwks/cache/caffeine/) demonstrate how this can be done. In this package there is: a CaffeineCache adaptor class, CaffeineCachingJwkSetService (which extends CachingJwkSetService) and a heaplet object which is used to construct and configure the caffeine caching. 

# FAPI Support
This module contains classes and Filters which can help with achieving [FAPI](https://fapi.openid.net/) conformance.
https://fapi.openid.net/
## FAPIAdvancedDCRValidationFilter
This Filter can be used as part of an OAuth2 filter chain to validate that the OAuth2 DCR request will produce a FAPI compliant OAuth2 client. 
Specifically, the filter is applying  validation rules as per the [FAPI1 Advanced spec](https://openid.net/specs/openid-financial-api-part-2-1_0.html)

The Filter should be configured in the chain before the filters which actually implement DCR. This means that typically the filter should go near the start of the chain.

The Filter only does validation and is agnostic of the particular API for which DCR is being done, such as Open Banking UK.
Therefore, it is the task of the filters later in the chain to implement DCR and API specific validations.

### Config
Minimum configuration to use the Filter:
```
{
          "comment": "Validate that the request will result in an OAuth2 client that is FAPI compliant,
          "name": "FAPIAdvancedDCRValidationFilter",
          "type": "FAPIAdvancedDCRValidationFilter",
          "config": {
            "clientTlsCertHeader": "ssl-client-cert"
          }
}
```
Filter configuration for Open Banking UK:
```
{
          "comment": "Validate that the request will result in an OAuth2 client that is FAPI compliant",
          "name": "FAPIAdvancedDCRValidationFilter",
          "type": "FAPIAdvancedDCRValidationFilter",
          "config": {
            "clientTlsCertHeader": "ssl-client-cert",
            "supportedSigningAlgorithms": ["PS256"],
            "supportedTokenEndpointAuthMethods": ["tls_client_auth", "private_key_jwt"]
          }
}
```

| config option                       | type     | description                                                                                                                                                                                                                                                   | default                                                                                           | Open Banking UK                                                                                        |
|-------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| clientTlsCertHeader                 | string   | The name of the header in which the client's TLS certificate can be found.<br/>The cert should be a x509 cert which is PEM encoded then URL encoded<br/>The `ssl-client-cert` value used in our example, is the header that nginx will add the client cert to | None, this must be configured                                                                     | Must be configured                                                                                     |
| supportedSigningAlgorithms          | string[] | The JWS algorithms supported for messaging signing                                                                                                                                                                                                            | ["PS256", "ES256"]                                                                                | ["PS256"]<br/>OB is more restrictive and only permits the use of PS256                                 |
| supportedTokenEndpointAuthMethods   | string[] | The DCR token_endpoint_auth_methods supported                                                                                                                                                                                                                 | ["tls_client_auth", "self_signed_tls_client_auth", "private_key_jwt"]                             | ["tls_client_auth", "private_key_jwt"]<br/>Or just one of these methods if the ASPSP only supports one |
| registrationObjectSigningFieldNames | string[] | The fields within the registration request object to validate against the supportedSigningAlgorithms                                                                                                                                                          | ["token_endpoint_auth_signing_alg", "id_token_signed_response_alg", "request_object_signing_alg"] | As per the default                                                                                     |


