import static java.lang.String.format
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import static org.forgerock.json.JsonValue.field

import groovy.json.JsonSlurper
import org.forgerock.http.protocol.*
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.json.JsonValue
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jws.*
import org.forgerock.json.jose.common.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.openig.fapi.apiclient.*
import org.forgerock.openig.tools.jwt.validation.*
import org.forgerock.secrets.jwkset.*
import org.forgerock.secrets.*
import com.forgerock.securebanking.uk.gateway.jwks.*
import org.forgerock.util.time.Duration

import java.text.ParseException
import java.time.Instant

import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.openig.fapi.jwks.JwkSetServicePurposes.signingPurpose;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;

/*
 * JWS spec: https://www.rfc-editor.org/rfc/rfc7515#page-7
 */
/**
 * Subject to waiver for earlier versions as per
 * https://openbanking.atlassian.net/wiki/spaces/DZ/pages/1112670669/W007
 *
 * If ASPSPs are still using v3.1.3 or earlier, they must support the parameter b64 to be false,
 * and any TPPs using these ASPSPs must do the same.
 *
 * If ASPSPs have updated to v3.1.4 or later, they must not include the b64 claim in the header,
 * and any TPPs using these ASPSPs must do the same.
 *
 */

SCRIPT_NAME = null
IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"
SUPPORTED_SIGNING_ALGORITHMS = List.of("PS256")

scriptInit(request)
filter(context, request, next)

/**
 * Initialises the script.
 * @param request the request
 */
void scriptInit(Request request) {
    def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
    if (fapiInteractionId == null) {
        fapiInteractionId = "No x-fapi-interaction-id"
    }
    jwtReconstruction = new JwtReconstruction().recognizedHeaders(IAT_CRIT_CLAIM, ISS_CRIT_CLAIM, TAN_CRIT_CLAIM)
    SCRIPT_NAME = "[ProcessDetachedSig] (" + fapiInteractionId + ") - "
    logger.debug(SCRIPT_NAME + "Running...")
}

/**
 * Script filter method
 * @param context the context
 * @param request the request
 * @param next the next handler
 * @return A promise containing a response
 */
Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
    // routeArgClockSkewAllowance is a org.forgerock.util.time.Duration
    // (see docs: https://backstage.forgerock.com/docs/ig/2024.3/reference/preface.html#definition-duration)
    clockSkewAllowance = Duration.duration(routeArgClockSkewAllowance).toJavaDuration()
    logger.info(SCRIPT_NAME + "Configured clock skew allowance: " + clockSkewAllowance)

    def method = request.method
    if (method != "POST") {
        //This script should be executed only if it is a POST request
        logger.debug(SCRIPT_NAME + "Skipping the filter because the method is not POST, the method is " + method)
        return next.handle(context, request)
    }

    // Parse api version from the request path
    logger.debug(SCRIPT_NAME + "request.uri.path: " + request.uri.path)
    String apiVersionRegex = "(v(\\d+.)?(\\d+.)?(\\*|\\d+))"
    def match = (request.uri.path =~ apiVersionRegex)
    def apiVersion = "";
    if (match.find()) {
        apiVersion = match.group(1)
        logger.debug(SCRIPT_NAME + "API version: " + apiVersion)
    } else {
        return fail(Status.BAD_REQUEST, "Can't parse API version for inbound request")
    }

    logger.debug(SCRIPT_NAME + "Building JWT from detached header")
    // JWS detached signature pattern: 'JWSHeader..JWSSignature' with no JWS payload
    def jwsDetachedSignatureHeader = request.headers.get(routeArgHeaderName)
    if (jwsDetachedSignatureHeader == null) {
        return fail(Status.BAD_REQUEST, "No detached signature header on inbound request " + routeArgHeaderName)
    }

    String detachedSignatureValue = jwsDetachedSignatureHeader.firstValue.toString()
    logger.debug(SCRIPT_NAME + "Inbound detached signature: " + detachedSignatureValue)
    String[] signatureElements = detachedSignatureValue.split("\\.")
    if (signatureElements.length != 3) {
        return fail(Status.BAD_REQUEST,
                    "Wrong number of dots on inbound detached signature " + signatureElements.length)
    }
    // Get the JWS header, first part of array
    String jwsHeaderEncoded = signatureElements[ 0 ]

    // Check JWS header for b64 claim:
    // - If claim is present, and API version > 3.1.3 then reject
    // - If claim is present, and is set to false, and API < 3.1.4 then accept and validate as non base64 payload

    String jwsHeaderDecoded = new String(jwsHeaderEncoded.decodeBase64Url())
    logger.debug(SCRIPT_NAME + "Got JWT header: " + jwsHeaderDecoded)
    def jwsHeaderDataStructure = new JsonSlurper().parseText(jwsHeaderDecoded)

    if ([ 'v3.0', 'v3.1.0', 'v3.1.1', 'v3.1.2', 'v3.1.3' ].contains(apiVersion)) {
        //Processing pre v3.1.4 requests
        if (jwsHeaderDataStructure.b64 == null) {
            message = "B64 header must be presented in JWT header before v3.1.3"
            logger.error(SCRIPT_NAME + message)
            return getSignatureValidationErrorResponse()
        } else if (jwsHeaderDataStructure.b64 != false) {
            message = "B64 header must be false in JWT header before v3.1.3"
            logger.error(SCRIPT_NAME + message)
            return getSignatureValidationErrorResponse()
        }
        //Processing post v3.1.4 requests
    } else if (jwsHeaderDataStructure.b64 != null) {
        message = "B64 header not permitted in JWT header after v3.1.3"
        logger.error(SCRIPT_NAME + message)
        return fail(Status.UNAUTHORIZED, "Signature validation failed")
    }

    // Validate the signed-JWT (against the "sig" keys).
    String[] jwtElements = detachedSignatureValue.split("\\.")
    String requestPayload = request.entity.getString()
    String rebuiltJwt
    if ([ 'v3.0', 'v3.1.0', 'v3.1.1', 'v3.1.2', 'v3.1.3' ].contains(apiVersion)) {
        rebuiltJwt = jwtElements[ 0 ] + "." + requestPayload + "." + jwtElements[ 2 ]
    } else {
        // v3.1.4 and higher
        // The payload must be encoded with base64Url
        rebuiltJwt = jwtElements[ 0 ] + "." +
                Base64.getUrlEncoder().withoutPadding().encodeToString(requestPayload.getBytes()) + "." +
                jwtElements[ 2 ]
    }
    def signedJwt = jwtReconstruction.reconstructJwt(rebuiltJwt, SignedJwt.class)
    return apiClient().getJwkSetSecretStore()
                      .thenAsync(jwkSetSecretStore -> validateJwt(signedJwt, jwkSetSecretStore))
                      .thenAsync(ignored -> next.handle(context, request))
}

private Promise<Void, NeverThrowsException> validateJwt(final SignedJwt signedJwt,
                                                                       final JwkSetSecretStore jwkSetSecretStore) {
    return buildJwtValidator(jwkSetSecretStore).report(signedJwt)
                                               .then(handleValidationResult(signedJwt),
                                                     neverThrown());
}

private JwtValidator buildJwtValidator(jwkSetSecretStore) {
    // XXX: This could be partially built on construction, and just add the call specific parts and #build() here
    // - e.g. the `hasValidSignature`, "iat", "exp", "tan"... are request specific.
    return JwtValidator.builder(clock)
                       .withSkewAllowance(routeArgClockSkewAllowance)
                       .jwt(hasSupportedSigningAlgorithm())
                       .jwt(hasValidSignature(new SecretsProvider(clock).setDefaultStores(jwkSetSecretStore),
                                              signingPurpose()))
                       .jwt(validateIss())
                       .jwt(validateType())
                       .jwt(validateIat())
                       .jwt(validateTan())
                       .build()
}

private JwtConstraint hasSupportedSigningAlgorithm() {
    return { context ->
        {
            if (SUPPORTED_SIGNING_ALGORITHMS.contains(context.getJwt().getHeader().getAlgorithm())) {
                return success().asPromise();
            }
            return failure(new Violation("Expected JWT to be signed using one of the supported 'alg' values: "
                                                 + SUPPORTED_SIGNING_ALGORITHMS)).asPromise();
        }
    } as JwtConstraint
}

// Validate the "http://openbanking.org.uk/iss" claim
//
// OB Spec:
// If the issuer is using a signing key lodged with a Trust Anchor, the value is defined by the Trust Anchor and
// should uniquely identify the PSP.
// For example, when using the Open Banking Directory, the value must be:
// - When issued by a TPP, of the form {{org-id}}/{{software-statement-id}},
private JwtConstraint validateIss() {
    return { context ->
        {
            def issCritClaim = context.getJwt().getHeader().getParameter(ISS_CRIT_CLAIM)
            if (issCritClaim == null) {
                return failure(new Violation(format("Expected value for header '%s' to be not null", ISS_CRIT_CLAIM))).
                        asPromise();
            }
            def apiClient = apiClient()
            def orgId = apiClient.getOrganisation().id()
            def softwareStatementId = apiClient.getSoftwareId()
            def expectedIssuerValue = orgId + "/" + softwareStatementId
            if (expectedIssuerValue != issCritClaim) {
                logger.error(SCRIPT_NAME + "Invalid " + ISS_CRIT_CLAIM +
                                     " value, expected: " + expectedIssuerValue +
                                     " actual: " + issCritClaim)
                return failure(new Violation(format("Expected value for header '%s' to be equal to %s",
                                                    ISS_CRIT_CLAIM,
                                                    expectedIssuerValue))).asPromise();
            }
            logger.debug(SCRIPT_NAME + ISS_CRIT_CLAIM + " is valid")
            return success().asPromise();
        }
    } as JwtConstraint
}

//optional header - only if it's found verify that it's mandatory equal to "JOSE"
private JwtConstraint validateType() {
    return { context ->
        {
            def type = context.getJwt().getHeader().getType()
            if (type == null) {
                return success().asPromise();
            }
            if (type.equals("JOSE")) {
                return success().asPromise()
            }
            return failure(new Violation("Expected value for type to be to 'JOSE'")).asPromise()
        }
    } as JwtConstraint
}

private JwtConstraint validateIat() {
    return { context ->
        {
            def iatClaim = context.getJwt().getHeader().getParameter(IAT_CRIT_CLAIM)
            if (iatClaim == null) {
                logger
                        .error(SCRIPT_NAME + "Could not validate detached JWT - required claim: " + IAT_CRIT_CLAIM +
                                       " " +
                                       "not found")
                return false
            }

            def iatTimestamp = Instant.ofEpochSecond(Long.valueOf(iatClaim))
            def skewedIatTimestamp = iatTimestamp.minus(clockSkewAllowance)
            def currentTimestamp = Instant.now()
            if (skewedIatTimestamp.isAfter(currentTimestamp)) {
                logger.error(SCRIPT_NAME + "Could not validate detached JWT - claim: " + IAT_CRIT_CLAIM +
                                     " must be in the past, value: " + iatTimestamp.getEpochSecond() +
                                     ", current time: " + currentTimestamp.getEpochSecond() +
                                     ", clockSkewAllowance: " + clockSkewAllowance)
                return false
            }
            logger.debug(SCRIPT_NAME + "Found valid iat!")
        }
    } as JwtConstraint
}

private JwtConstraint validateTan() {
    return { context ->
        {
            def tanClaim = context.getJwt().getHeader().getParameter(TAN_CRIT_CLAIM)
            if (tanClaim == null || tanClaim != routeArgTrustedAnchor) {
                logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid trusted anchor found: " +
                                     tanClaim + " expected: " + routeArgTrustedAnchor)
                return failure(new Violation(format("Expected value for '%s' to be to '%s'", TAN_CRIT_CLAIM,
                                                    routeArgTrustedAnchor))).asPromise()
            }
            return success().asPromise()
        }
    } as JwtConstraint
}

private Function<JwtValidatorResult, Void, NeverThrowsException> handleValidationResult() {
    return { validationResult ->
        {
            if (!validationResult.isValid()) {
                logger.debug("Request JWT is invalid - constraint violations: {}",
                             validationResult.getViolationsAsString())
                throw new IllegalStateException("Registration Request JWT is invalid: "
                                                        + validationResult.getViolationsAsString());
            }
        }
    } as Function<JwtValidatorResult, Void, NeverThrowsException>
}

ApiClient apiClient() {
    def apiClientFapiContext = context.asContext(ApiClientFapiContext.class)
    def apiClientOpt = apiClientFapiContext.getApiClient()
    if (apiClientOpt.isEmpty()) {
        logger.error("apiClient must be identified before this script - it should exist in the ApiClientFapiContext")
        throw new IllegalStateException("Route is configured incorrectly, " + SCRIPT_NAME +
                                                "requires apiClient context attribute")
    }
    return apiClientOpt.get()
}

/**
 * Report a processing failure.
 * @param status HTTP status
 * @param message error message
 * @return Pomise of a response
 */
Promise<Response, NeverThrowsException> fail(Status status, String message) {
    logger.error(SCRIPT_NAME + message)
    response = new Response(status)
    response.headers[ 'Content-Type' ] = "application/json"
    response.getEntity().setJson(json(object(field("error", message))))
    return newResponsePromise(response)
}

