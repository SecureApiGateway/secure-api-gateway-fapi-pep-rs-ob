import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt
import java.net.URI
import groovy.json.JsonSlurper
import com.forgerock.securebanking.uk.gateway.jwks.*
import com.nimbusds.jose.jwk.RSAKey;
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 */

SCRIPT_NAME = "[ProcessRegistration] - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponse(httpCode, message) {
    logger.error(SCRIPT_NAME + "Returning error " + httpCode + ": " + message);
    def response = new Response(httpCode);
    response.headers['Content-Type'] = "application/json";
    response.entity = "{ \"error\":\"" + message + "\"}";
    return response;
}

def defaultResponseTypes =  ["code id_token"]
def supportedResponseTypes = [defaultResponseTypes]

def method = request.method

switch(method.toUpperCase()) {
    case "POST":
    case "PUT":
        def error = false

        def SCOPE_ACCOUNTS = "accounts"
        def SCOPE_PAYMENTS = "payments"


        def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
        def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
        def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

        // Check we have everything we need from the client certificate

        if (!attributes.clientCertificate) {
            return(errorResponse(Status.BAD_REQUEST,"No client certificate for registration"));
        }

        if (!attributes.clientCertificate.roles) {
            return(errorResponse(Status.BAD_REQUEST,"No roles in client certificate for registration"));
        }

        // Parse incoming registration JWT

        logger.debug(SCRIPT_NAME + "Parsing registration request");

        def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

        // TODO: Check signature

        // Pull the SSA from the reg data

        def oidcRegistration = regJwt.getClaimsSet()

        // Valid exp claim
        Date expirationTime = oidcRegistration.getExpirationTime()
        if (expirationTime.before(new Date())) {
            return errorResponse(Status.BAD_REQUEST,"registration has expired")
        }

        def responseTypes = oidcRegistration.getClaim("response_types")
        if (!responseTypes) {
            oidcRegistration.setClaim("response_types", defaultResponseTypes)
        } else if (!supportedResponseTypes.contains(responseTypes)) {
            return errorResponse(Status.BAD_REQUEST, "response_types: " + responseTypes + " not supported")
        }

        def ssa = oidcRegistration.getClaim("software_statement", String.class);
        if (!ssa) {
            return(errorResponse(Status.BAD_REQUEST,"No SSA"));
        }
        oidcRegistration.setClaim("software_statement",null);

        logger.debug(SCRIPT_NAME + "Got ssa [" + ssa + "]")

        def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)

        def ssaClaims = ssaJwt.getClaimsSet();

        // Validate the issuer claim for the registration matches the SSA software_id
        // NOTE: At this stage we do not know if the SSA is valid, it is assumed the SSAVerifier filter will run after
        //       this filter and raise an error if the SSA is invalid.
        def registrationIssuer = oidcRegistration.getIssuer()
        def ssaSoftwareId = ssaClaims.getClaim("software_id")
        if (registrationIssuer == null || ssaSoftwareId == null || registrationIssuer != ssaSoftwareId) {
            return errorResponse(Status.BAD_REQUEST,"invalid issuer claim")
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
            logger.debug(SCRIPT_NAME + "Using jwks uri")
            if (routeArgObJwksHosts) {

                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG

                def slurper = new JsonSlurper()
                def proxiedHosts = slurper.parseText(routeArgObJwksHosts);

                if (!proxiedHosts) {
                    return(errorResponse(Status.INTERNAL_SERVER_ERROR,"Could not parse proxied jwks hosts"));
                }
                def jwksUri = null;
                try {
                    jwksUri = new URI(apiClientOrgJwksUri);
                }
                catch (e) {
                    return(errorResponse(Status.BAD_REQUEST,"Invalid JWKS URI: " + apiClientOrgJwksUri));
                }

                if (proxiedHosts.asList().contains(jwksUri.getHost())) {
                    def newUri = routeArgProxyBaseUrl + "/" + jwksUri.getHost() + jwksUri.getPath();
                    logger.debug(SCRIPT_NAME + "Updating private JWKS URI from {} to {}",apiClientOrgJwksUri,newUri);
                    apiClientOrgJwksUri = newUri;

                }
            }
            oidcRegistration.setClaim("jwks_uri", apiClientOrgJwksUri)
        }
        else if (apiClientOrgJwks) {
            if (!allowIgIssuedTestCerts) {
                logger.debug("configuration to allowIgIssuedTestCerts is disabled")
                return(errorResponse(Status.BAD_REQUEST, "software_statement must contain software_jwks_endpoint"));
            }
            logger.debug(SCRIPT_NAME + "Using jwks from software_statement")
            oidcRegistration.setClaim("jwks",  apiClientOrgJwks )
        }
        else {
            return(errorResponse(Status.BAD_REQUEST,"No JWKS or JWKS URI in SSA"));
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
            return(errorResponse(Status.BAD_REQUEST,"Requested scope " + SCOPE_ACCOUNTS + " requires certificate role " + ROLE_ACCOUNT_INFORMATION));
        }

        if (scopes.contains(SCOPE_PAYMENTS) && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
            return(errorResponse(Status.BAD_REQUEST,"Requested scope " + SCOPE_PAYMENTS + " requires certificate role " + ROLE_PAYMENT_INITIATION));
        }

        // Cross check ID with cert
        //
        // e.g. PSDGB-FFA-5f563e89742b2800145c7da1 or PSDGB-OB-Unknown0015800001041REAAY (issue by OB)

        def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

        if (!organizationalIdentifier) {
            return(errorResponse(Status.BAD_REQUEST,"No organizational identifier in cert"));
        }

        def oiComponents = organizationalIdentifier.split("-")

        if (oiComponents.length > 3) {
            return(errorResponse(Status.BAD_REQUEST,"Wrong number of dashes in OI " + organizationalIdentifier +" - expected 2"));
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
                                    logger.debug(SCRIPT_NAME + "failed to get jwks due to exception", e)
                                    return newResultPromise(errorResponse(Status.BAD_REQUEST, "unable to get jwks from url: " + apiClientOrgJwksUri))
                                })
                                .thenAsync(jwtSet -> {
                                    if (!tlsClientCertExistsInJwkSet(jwtSet)) {
                                        return newResultPromise(errorResponse(Status.BAD_REQUEST, "tls transport cert does not match any certs registered in jwks for software statement"))
                                    }
                                    return next.handle(context, request)
                                               .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
                                })

        } else {
            // Verify against the software_jwks which is a JWKSet embedded within the software_statement
            // NOTE: this is only suitable for developer testing purposes
            if (!allowIgIssuedTestCerts) {
                return(errorResponse(Status.BAD_REQUEST, "software_statement must contain software_jwks_endpoint"));
            }
            logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientOrgJwks)
            def jwkSet = new JWKSet(new JsonValue(apiClientOrgJwks.get("keys")))
            if (!tlsClientCertExistsInJwkSet(jwtSet)) {
                return newResultPromise(errorResponse(Status.BAD_REQUEST, "tls transport cert does not match any certs registered in jwks for software statement"))
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
