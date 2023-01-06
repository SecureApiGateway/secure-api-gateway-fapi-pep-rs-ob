import com.forgerock.sapi.gateway.jwt.JwtUtils
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory
import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import org.forgerock.json.JsonValue
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwt.Jwt
import java.net.URI
import groovy.json.JsonSlurper
import com.forgerock.securebanking.uk.gateway.jwks.*
import java.security.SignatureException
import com.nimbusds.jose.jwk.RSAKey;
import com.securebanking.gateway.dcr.ErrorResponseFactory
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 *
 * Relevant specifications:
 * https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping
 * https://openid.net/specs/openid-connect-registration-1_0.html
 * https://datatracker.ietf.org/doc/html/rfc7591
 *
 * NOTE: This filter should be used AFTER the FAPIAdvancedDCRValidationFilter. That filter will check that the request
 * is fapi compliant:
 * - validateRedirectUris
 *   - request object must contain redirect_uris field
 *   - redirect_uris array must not be empty
 *   - redirect_uris contain valid URIs
 *   - redirect_uris must use https scheme
 * - validateResponseTypes
 *   - request object must contain field: response_types
 *   - response types are FAPI compliant, i.e. "code" or "code id_token"
 *   - if response type is "code", response_mode is "jwt"
 *   - if response type is "code id_token" then request must contain field 'scope' and scope must contain 'openid'
 * - validateSigningAlgorithmUsed
 *   - that the signing algorithm supported is PS256
 * - validateTokenEndpointAuthMethods
 *   - request object must contain field: token_endpoint_auth_method
 *   - that token_endpoint_auth_method is a valid value, either 'private_key_jwt' or 'tls_client_auth'
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ProcessRegistration] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def defaultResponseTypes = ["code id_token"]
def supportedResponseTypes = [defaultResponseTypes]

if (!trustedDirectoryService) {
    logger.error(SCRIPT_NAME + "No TrustedDirectoriesService defined on the heap in config.json")
    return new Response(Status.INTERNAL_SERVER_ERROR).body("No TrustedDirectoriesService defined on the heap in config.json")
}

def method = request.method

switch (method.toUpperCase()) {
    case "POST":
    case "PUT":
        def SCOPE_ACCOUNTS = "accounts"
        def SCOPE_PAYMENTS = "payments"
        def ROLE_PAYMENT_INITIATION = "0.4.0.19495.1.2"
        def ROLE_ACCOUNT_INFORMATION = "0.4.0.19495.1.3"
        def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

        // Check we have everything we need from the client certificate
        if (!attributes.clientCertificate) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No client certificate for registration")
        }
        if (!attributes.clientCertificate.roles) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No roles in client certificate for registration")
        }

        Jwt regJwt = JwtUtils.getSignedJwtFromString(SCRIPT_NAME, request.entity.getString(), "registration JWT")
        if (!regJwt) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        }

        JwtClaimsSet registrationJwtClaimSet = regJwt.getClaimsSet()
        if (JwtUtils.hasExpired(registrationJwtClaimSet)) {
            logger.debug(SCRIPT_NAME + "Registration request JWT has expired")
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration has expired")
        }

        def responseTypes = registrationJwtClaimSet.getClaim("response_types")
        if (!responseTypes) {
            registrationJwtClaimSet.setClaim("response_types", defaultResponseTypes)
        } else if (!supportedResponseTypes.contains(responseTypes)) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("response_types: " + responseTypes + " not supported")
        }

        def tokenEndpointAuthMethod = registrationJwtClaimSet.getClaim("token_endpoint_auth_method")
        if (!tokenEndpointAuthMethod || !tokenEndpointAuthMethodsSupported.contains(tokenEndpointAuthMethod)) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("token_endpoint_auth_method claim must be one of: " + tokenEndpointAuthMethodsSupported)
        }

        def ssa = registrationJwtClaimSet.getClaim("software_statement", String.class);
        if (!ssa) {
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement claim is missing")
        }
        logger.debug(SCRIPT_NAME + "Got ssa [" + ssa + "]")

        // This is nulled down because currently the SSA issued by the Open Banking Test Directory is not valid and is
        // rejected by AM. This is set to change when OBIE release a new version of the Directory in Feb 2023.
        registrationJwtClaimSet.setClaim("software_statement", null);

        Jwt ssaJwt = JwtUtils.getSignedJwtFromString(SCRIPT_NAME, ssa, "SSA")
        if (!ssaJwt) {
            logger.warn(SCRIPT_NAME + "failed to decode software_statement JWT", e)
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement is not a valid JWT")
        }

        def ssaClaims = ssaJwt.getClaimsSet();
        String ssaIssuer = ssaClaims.getIssuer()
        if (ssaIssuer == null || ssaIssuer.isBlank()) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("Registration jwt must contain an issuer")
        }
        logger.debug(SCRIPT_NAME + "issuer is {}", ssaIssuer)

        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer)
        if (trustedDirectory) {
            logger.debug(SCRIPT_NAME + "Found trusted directory for issuer '" + ssaIssuer + "'")
        } else {
            logger.debug(SCRIPT_NAME + "Could not find Trusted Directory for issuer '" + ssaIssuer + "'")
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("issuer: " + ssaIssuer + " is not supported")
        }

        try {
            validateRegistrationRedirectUris(registrationJwtClaimSet, ssaClaims)
        } catch (e) {
            logger.warn(SCRIPT_NAME + "failed to validate redirect_uris", e)
            return errorResponseFactory.invalidRedirectUriErrorResponse(e.getMessage())
        }

        // Validate the issuer claim for the registration matches the SSA software_id
        // NOTE: At this stage we do not know if the SSA is valid, it is assumed the SSAVerifier filter will run after
        //       this filter and raise an error if the SSA is invalid.
        String registrationIssuer = registrationJwtClaimSet.getIssuer()
        String ssaSoftwareId = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementSoftwareIdClaimName())
        logger.debug("{}registrationIssuer is {}, ssaSoftwareId is {}", SCRIPT_NAME, registrationIssuer, ssaSoftwareId)
        if (registrationIssuer == null || ssaSoftwareId == null || registrationIssuer != ssaSoftwareId) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("invalid issuer claim")
        }

        def apiClientOrgName = ssaClaims.getClaim("software_client_name", String.class);
        def apiClientOrgCertId = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementOrgIdClaimName(), String.class);

        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {}",
                apiClientOrgName,
                apiClientOrgCertId
        )

        def registrationJWTs = [
                "ssaStr"             : ssa,
                "ssaJwt"             : ssaJwt,
                "registrationJwt"    : regJwt,
                "registrationJwksUri": null,
                "registrationJwks"   : null
        ]


        // Update OIDC registration request
        if (trustedDirectory.softwareStatementHoldsJwksUri()) {
            def apiClientOrgJwksUri = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementJwksUriClaimName());
            logger.debug(SCRIPT_NAME + "Using jwks uri: {}", apiClientOrgJwksUri)
            registrationJwtClaimSet.setClaim("jwks_uri", apiClientOrgJwksUri)
            registrationJWTs["registrationJwksUri"] = apiClientOrgJwksUri
        } else {
            def apiClientJwks = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementJwksClaimName());
            logger.debug(SCRIPT_NAME + "Using jwks from software_statement")
            registrationJwtClaimSet.setClaim("jwks", apiClientJwks)
            registrationJWTs["registrationJwks"] = apiClientJwks
        }

        // The Jwks will be added by filters run on each route... we won't need  to store them here.
        // Store SSA and registration JWT for signature check
        attributes.registrationJWTs = registrationJWTs

        registrationJwtClaimSet.setClaim("client_name", apiClientOrgName)
        registrationJwtClaimSet.setClaim("tls_client_certificate_bound_access_tokens", true)

        // Why is this here?
        def subject_type = registrationJwtClaimSet.getClaim("subject_type", String.class);
        if (!subject_type) {
            registrationJwtClaimSet.setClaim("subject_type", "pairwise");
        }

        Response errorResponse = performOpenBankingScopeChecks(errorResponseFactory, registrationJwtClaimSet, ssaClaims)
        if (errorResponse != null) {
            return errorResponse
        }

        // TODO: Subject DN for cert bound access tokens

        // Convert to JSON and pass it on
        def regJson = registrationJwtClaimSet.build();
        logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
        request.setEntity(regJson)

        // Put is editing an existing registration, so needs the client_id param in the uri
        if (request.method == "PUT") {
            rewriteUriToAccessExistingAmRegistration()
        }

        // Verify that the tls transport cert is registered for the TPP's software statement
        if (trustedDirectory.softwareStatementHoldsJwksUri()) {
            URL apiClientOrgJwksUri = new URL(registrationJWTs["registrationJwksUri"])
            logger.debug(SCRIPT_NAME + "Checking cert against remote jwks: " + apiClientOrgJwksUri)
            return jwkSetService.getJwkSet(apiClientOrgJwksUri)
                .thenCatchAsync(e -> {
                    String errorDescription = "Unable to get jwks from url: " + apiClientOrgJwksUri
                    logger.warn(SCRIPT_NAME + "Failed to get jwks due to exception: " + errorDescription, e)
                    return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
                })
                .thenAsync(jwkSet -> {
                    if (!tlsClientCertExistsInJwkSet(jwkSet)) {
                        String errorDescription = "tls transport cert does not match any certs " +
                                "registered in jwks for software statement"
                        logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                        return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
                    }
                    if (!validateRegistrationJwtSignature(regJwt, jwkSet)) {
                        String errorDescription = "registration JWT signature invalid"
                        logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                        return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
                    }
                    return next.handle(context, request)
                            .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
                })
        } else {
            // Verify against the software_jwks which is a JWKSet embedded within the software_statement
            // NOTE: this is only suitable for developer testing purposes
            if (!allowIgIssuedTestCerts) {
                String errorDescription = "software_statement must contain software_jwks_endpoint"
                return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
            }
            def apiClientOrgJwks = registrationJWTs["registrationJwks"]
            logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientOrgJwks)
            def jwkSet = new JWKSet(new JsonValue(apiClientOrgJwks.get("keys")))
            if (!tlsClientCertExistsInJwkSet(jwkSet)) {
                String errorDescription = "tls transport cert does not match any certs registered in jwks for software " +
                        "statement"
                logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
            }
            if (!validateRegistrationJwtSignature(regJwt, jwkSet)) {
                String errorDescription = "registration JWT signature invalid"
                logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
            }
            return next.handle(context, request)
                    .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
        }

    case "DELETE":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
    case "GET":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
                .thenOnResult(response -> {
                    var apiClient = attributes.apiClient
                    if (apiClient && apiClient.ssa) {
                        addSoftwareStatementToResponse(response, apiClient.ssa)
                    }
                })
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return next.handle(context, request)

}

/**
 * This method enforces the rule set by OBIE
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping">here</a>
 * that states:
 * "scope: Specified in the scope claimed. This must be a subset of the scopes in the SSA"
 * also in the
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#obclientregistrationrequest1">
 * data dictionary for OBClientRegistrationRequest1 </a>
 * it is stated that:
 * "scope 	1..1 	scope 	Scopes the client is asking for (if not specified, default scopes are assigned by the AS).
 * This consists of a list scopes separated by spaces. 	String(256)"
 *
 * In the Open Banking issues SSA we can find no scopes defined, however, we do have 'software_roles' which is an array
 * of strings containing AISP, PISP, or a subset thereof, or ASPSP. We must check that the scopes requested are allowed
 * according to the roles defined in the software statement.
 *
 * @param registrationRequestClaims The claims from the registration request jwt
 * @param ssaClaims the claims from the ssa
 * @return false if the OBIE specification rules are met, true if they are not
 */
private Response performOpenBankingScopeChecks(ErrorResponseFactory errorResponseFactory,
                                               JwtClaimsSet registrationRequestClaims, JwtClaimsSet ssaClaims) {
    logger.debug("{}performing OpenBanking Scope tests", SCRIPT_NAME)
    String requestedScopes = registrationRequestClaims.getClaim("scope")
    if (requestedScopes == null) {
        String errorDescription = "The request jwt does not contain the required scopes claim"
        logger.info(SCRIPT_NAME + errorDescription)
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }
    logger.debug("{}requestedScopes are {}", SCRIPT_NAME, requestedScopes)

    String[] ssaRoles = ssaClaims.getClaim("software_roles")
    logger.debug("{}ssaRoles are {}", SCRIPT_NAME, ssaRoles)
    if (ssaRoles == null | ssaRoles.length == 0) {
        String errorDescription = "The software_statement jwt does not contain a 'software_roles' claim"
        logger.debug(SCRIPT_NAME + errorDescription)
        return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("accounts") && !ssaRoles.contains("AISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": accounts")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("payments") && !ssaRoles.contains("PISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": payments")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("fundsconformations") && !ssaRoles.contains("CBPII")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": fundsconformations")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    logger.debug("{} passed Open Banking scope tests", SCRIPT_NAME)
    return null;
}

/**
 * For operations on an existing registration, AM expects a uri of the form:
 *   am/oauth2/realms/root/realms/alpha/register?client_id=8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb
 *
 * This method takes the OB uri form: am/oauth2/realms/root/realms/alpha/8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb and
 * rewrites it to the AM form.
 */
private void rewriteUriToAccessExistingAmRegistration() {
    def path = request.uri.path
    def lastSlashIndex = path.lastIndexOf("/")
    def apiClientId = path.substring(lastSlashIndex + 1)
    request.uri.setRawPath(path.substring(0, lastSlashIndex))
    request.uri.setRawQuery("client_id=" + apiClientId)
}

private void addSoftwareStatementToResponse(response, ssa) {
    if (response.status.isSuccessful()) {
        var registrationResponse = response.getEntity().getJson()
        if (!registrationResponse["software_statement"]) {
            registrationResponse["software_statement"] = ssa
        }
        response.entity.setJson(registrationResponse)
    }
}

private boolean tlsClientCertExistsInJwkSet(jwkSet) {
    def tlsClientCert = attributes.clientCertificate.certificate
    // RSAKey.parse produces a JWK, we can then extract the cert from the x5c field
    def tlsClientCertX5c = RSAKey.parse(tlsClientCert).getX509CertChain().get(0).toString()
    for (JWK jwk : jwkSet.getJWKsAsList()) {
        final List<String> x509Chain = jwk.getX509Chain();
        final String jwkX5c = x509Chain.get(0);
        if ("tls".equals(jwk.getUse()) && tlsClientCertX5c.equals(jwkX5c)) {
            logger.debug(SCRIPT_NAME + "Found matching tls cert for provided pem, with kid: " + jwk.getKeyId()
                    + " x5t#S256: " + jwk.getX509ThumbprintS256())
            return true
        }
    }
    logger.debug(SCRIPT_NAME + "tls transport cert does not match any certs registered in jwks for software statement")
    return false
}

private boolean validateRegistrationJwtSignature(jwt, jwkSet) {
    try {
        jwtSignatureValidator.validateSignature(jwt, jwkSet)
        return true
    } catch (SignatureException se) {
        logger.warn(SCRIPT_NAME + "jwt signature validation failed", se)
        return false
    }
}

/**
 * Validate the redirect_uris claim in the registration request is valid as per the OB DCR spec:
 * https://openbankinguk.github.io/dcr-docs-pub/v3.2/dynamic-client-registration.html
 */
private void validateRegistrationRedirectUris(registrationJwtClaimSet, ssaClaims) {
    def regRedirectUris = registrationJwtClaimSet.getClaim("redirect_uris")
    def ssaRedirectUris = ssaClaims.getClaim("software_redirect_uris")
    if (!ssaRedirectUris || ssaRedirectUris.size() == 0) {
        throw new IllegalStateException("software_statement must contain redirect_uris")
    }
    // If no redirect_uris supplied in registration request, use all of the uris defined in software_redirect_uris
    if (!regRedirectUris || regRedirectUris.size() == 0) {
        registrationJwtClaimSet.setClaim("redirect_uris", ssaRedirectUris)
    } else {
        // validate registration redirects are the same as, or a subset of, software_redirect_uris
        if (regRedirectUris.size() > ssaRedirectUris.size()) {
            throw new IllegalStateException("invalid registration request redirect_uris value, must match or be a subset of the software_redirect_uris")
        } else {
            for (regRedirect in regRedirectUris) {
                def redirectUrl
                try {
                    redirectUrl = new URL(regRedirect)
                } catch (e) {
                    throw new IllegalStateException("invalid registration request redirect_uris value: " + regRedirect + " is not a valid URI")
                }
                if (!"https".equals(redirectUrl.getProtocol())) {
                    throw new IllegalStateException("invalid registration request redirect_uris value: " + regRedirect + " must use https")
                }
                if ("localhost".equals(redirectUrl.getHost())) {
                    throw new IllegalStateException("invalid registration request redirect_uris value: " + regRedirect + " must not point to localhost")
                }
                if (!ssaRedirectUris.contains(regRedirect)) {
                    throw new IllegalStateException("invalid registration request redirect_uris value, must match or be a subset of the software_redirect_uris")
                }
            }
        }
    }
}
