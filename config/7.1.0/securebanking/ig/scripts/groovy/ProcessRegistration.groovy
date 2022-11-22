import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt
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
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ProcessRegistration] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def defaultResponseTypes =  ["code id_token"]
def supportedResponseTypes = [defaultResponseTypes]

def method = request.method

switch(method.toUpperCase()) {
    case "POST":
    case "PUT":
        def SCOPE_ACCOUNTS = "accounts"
        def SCOPE_PAYMENTS = "payments"
        def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
        def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
        def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

        // Check we have everything we need from the client certificate
        if (!attributes.clientCertificate) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No client certificate for registration")
        }
        if (!attributes.clientCertificate.roles) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No roles in client certificate for registration")
        }

        // Parse incoming registration JWT
        logger.debug(SCRIPT_NAME + "Parsing registration request");
        def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

        // Pull the SSA from the reg data

        def oidcRegistration = regJwt.getClaimsSet()

        // Valid exp claim
        Date expirationTime = oidcRegistration.getExpirationTime()
        if (expirationTime.before(new Date())) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration has expired")
        }

        def responseTypes = oidcRegistration.getClaim("response_types")
        if (!responseTypes) {
            oidcRegistration.setClaim("response_types", defaultResponseTypes)
        } else if (!supportedResponseTypes.contains(responseTypes)) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("response_types: " + responseTypes + " not supported")
        }

        def ssa = oidcRegistration.getClaim("software_statement", String.class);
        if (!ssa) {
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement claim is missing")
        }
        logger.debug(SCRIPT_NAME + "Got ssa [" + ssa + "]")
        oidcRegistration.setClaim("software_statement", null);

        def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)
        def ssaClaims = ssaJwt.getClaimsSet();

        // Validate the issuer claim for the registration matches the SSA software_id
        // NOTE: At this stage we do not know if the SSA is valid, it is assumed the SSAVerifier filter will run after
        //       this filter and raise an error if the SSA is invalid.
        def registrationIssuer = oidcRegistration.getIssuer()
        def ssaSoftwareId = ssaClaims.getClaim("software_id")
        if (registrationIssuer == null || ssaSoftwareId == null || registrationIssuer != ssaSoftwareId) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("invalid issuer claim")
        }

        def apiClientOrgName = ssaClaims.getClaim("software_client_name", String.class);
        def apiClientOrgCertId = ssaClaims.getClaim("org_id", String.class);
        def apiClientOrgJwksUri = ssaClaims.getClaim("software_jwks_endpoint");
        def apiClientOrgJwks = ssaClaims.getClaim("software_jwks");

        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {} apiClientOrgJwksUri: {} apiClientOrgJwks: {}",
                apiClientOrgName,
                apiClientOrgCertId,
                apiClientOrgJwksUri,
                apiClientOrgJwks
        )

        // Update OIDC registration request
        if (apiClientOrgJwksUri) {
            logger.debug(SCRIPT_NAME + "Using jwks uri: {}", apiClientOrgJwksUri)
            if (routeArgObJwksHosts) {
                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG
                def jwksUri = null;
                try {
                    jwksUri = new URI(apiClientOrgJwksUri)
                }
                catch (e) {
                    return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_jwks_endpoint does not contain a valid URI")
                }
                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG
                if (routeArgObJwksHosts && routeArgObJwksHosts.contains(jwksUri.getHost())) {
                    def newUri = routeArgProxyBaseUrl + "/" + jwksUri.getHost() + jwksUri.getPath();
                    logger.debug(SCRIPT_NAME + "Updating private JWKS URI from {} to {}", apiClientOrgJwksUri, newUri);
                    apiClientOrgJwksUri = newUri

                }
            }
            oidcRegistration.setClaim("jwks_uri", apiClientOrgJwksUri)
        }
        else if (apiClientOrgJwks) {
            if (!allowIgIssuedTestCerts) {
                logger.debug(SCRIPT_NAME + "configuration to allowIgIssuedTestCerts is disabled")
                return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement must contain software_jwks_endpoint")
            }
            logger.debug(SCRIPT_NAME + "Using jwks from software_statement")
            oidcRegistration.setClaim("jwks",  apiClientOrgJwks )
        }
        else {
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("No JWKS or JWKS URI in software_statement")
        }

        // Store SSA and registration JWT for signature check
        attributes.registrationJWTs = [
                "ssaStr": ssa,
                "ssaJwt" : ssaJwt,
                "registrationJwt": regJwt,
                "registrationJwksUri": apiClientOrgJwksUri,
                "registrationJwks": apiClientOrgJwks
        ]

        oidcRegistration.setClaim("client_name",apiClientOrgName)
        oidcRegistration.setClaim("tls_client_certificate_bound_access_tokens", true)

        def subject_type = oidcRegistration.getClaim("subject_type", String.class);
        if(!subject_type){
            oidcRegistration.setClaim("subject_type", "pairwise");
        }

        // Sanity check on scopes
        def scopes = oidcRegistration.getClaim("scope")
        def roles = attributes.clientCertificate.roles
        if (scopes.contains(SCOPE_ACCOUNTS) && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("Requested scope " + SCOPE_ACCOUNTS + " requires certificate role " + ROLE_ACCOUNT_INFORMATION)
        }
        if (scopes.contains(SCOPE_PAYMENTS) && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("Requested scope " + SCOPE_PAYMENTS + " requires certificate role " + ROLE_PAYMENT_INITIATION)
        }

        // Cross check ID with cert
        //
        // e.g. PSDGB-FFA-5f563e89742b2800145c7da1 or PSDGB-OB-Unknown0015800001041REAAY (issue by OB)
        def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI
        if (!organizationalIdentifier) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No organizational identifier in cert")
        }

        def oiComponents = organizationalIdentifier.split("-")
        if (oiComponents.length > 3) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("Wrong number of dashes in OI " + organizationalIdentifier +" - expected 2")
        }

        // TODO: Subject DN for cert bound access tokens

        // Convert to JSON and pass it on
        def regJson = oidcRegistration.build();
        logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
        request.setEntity(regJson)

        // Put is editing an existing registration, so needs the client_id param in the uri
        if (request.method == "PUT") {
            rewriteUriToAccessExistingAmRegistration()
        }

        // Verify that the tls transport cert is registered for the TPP's software statement
        if (apiClientOrgJwksUri != null) {
            logger.debug(SCRIPT_NAME + "Checking cert against remote jwks: " + apiClientOrgJwksUri)
            return jwkSetService.getJwkSet(new URL(apiClientOrgJwksUri))
                                .thenCatchAsync(e -> {
                                    logger.warn(SCRIPT_NAME + "failed to get jwks due to exception", e)
                                    return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse("unable to get jwks from url: " + apiClientOrgJwksUri))
                                })
                                .thenAsync(jwkSet -> {
                                    if (!tlsClientCertExistsInJwkSet(jwkSet)) {
                                        return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse("tls transport cert does not match any certs registered in jwks for software statement"))
                                    }
                                    if (!validateRegistrationJwtSignature(regJwt, jwkSet)) {
                                        return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse("registration JWT signature invalid"))
                                    }
                                    return next.handle(context, request)
                                               .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
                                })

        } else {
            // Verify against the software_jwks which is a JWKSet embedded within the software_statement
            // NOTE: this is only suitable for developer testing purposes
            if (!allowIgIssuedTestCerts) {
                return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement must contain software_jwks_endpoint")
            }
            logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientOrgJwks)
            def jwkSet = new JWKSet(new JsonValue(apiClientOrgJwks.get("keys")))
            if (!tlsClientCertExistsInJwkSet(jwkSet)) {
                return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse( "tls transport cert does not match any certs registered in jwks for software statement"))
            }
            if (!validateRegistrationJwtSignature(regJwt, jwkSet)) {
                return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse("registration JWT signature invalid"))
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
            logger.debug(SCRIPT_NAME + "Found matching tls cert for provided pem, with kid: " + jwk.getKeyId() + " x5t#S256: " + jwk.getX509ThumbprintS256())
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
