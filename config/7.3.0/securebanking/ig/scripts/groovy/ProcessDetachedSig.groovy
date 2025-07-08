import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import static org.forgerock.json.JsonValue.field

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import groovy.json.JsonSlurper
import org.forgerock.http.protocol.*
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.json.JsonValue
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.JWK
import org.forgerock.json.jose.jwk.JWKSet
import org.forgerock.json.jose.jwk.RsaJWK
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException
import org.forgerock.json.jose.jwk.store.JwksStore.*
import com.forgerock.securebanking.uk.gateway.jwks.*
import java.security.interfaces.RSAPublicKey
import org.forgerock.util.time.Duration

import java.text.ParseException
import java.time.Instant

import static org.forgerock.http.protocol.Response.newResponsePromise

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
 * This script relies on the apiClient attribute being set, therefore must be installed after the FetchApiClientFilter
 */

SCRIPT_NAME = null

IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"

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

    apiClient().getJwkSet().thenAsync(jwkSet -> {
        if (!jwkSet) {
            logger.error(SCRIPT_NAME + "apiClient JwkSet not found, ensure that filter which configures the " +
                                   "apiClient JwkSet is installed prior to this filter in the chain")
            return newResponsePromise(new Response(Status.INTERNAL_SERVER_ERROR))
        }

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
            } else {
                String requestPayload = request.entity.getString()
                try {
                    logger.debug(SCRIPT_NAME + "Processing Unencoded payload request")
                    if (!validateUnencodedPayload(detachedSignatureValue, jwkSet, requestPayload)) {
                        return fail(Status.UNAUTHORIZED, "Signature validation failed")
                    }
                    return next.handle(context, request)
                }
                catch (Exception e) {
                    logger.error(SCRIPT_NAME + "Exception validating the detached jws: " + e)
                    return fail(Status.UNAUTHORIZED, "Signature validation failed")
                }
            }
        } else {
            //Processing post v3.1.4 requests
            if (jwsHeaderDataStructure.b64 != null) {
                message = "B64 header not permitted in JWT header after v3.1.3"
                logger.error(SCRIPT_NAME + message)
                return fail(Status.UNAUTHORIZED, "Signature validation failed")
            }

            String requestPayload = request.entity.getString()
            try {
                logger.debug(SCRIPT_NAME + "Standard base64 encoded payload for detached sig")
                if (!validateEncodedPayload(detachedSignatureValue, jwkSet, requestPayload)) {
                    return fail(Status.UNAUTHORIZED, "Signature validation failed")
                }
                return next.handle(context, request)
            }
            catch (Exception e) {
                logger.error(SCRIPT_NAME + "Exception validating the detached jws: " + e)
                return fail(Status.UNAUTHORIZED, "Signature validation failed")
            }
        }
    })
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

/**
 * Validates a request with unencoded payload. Between Version 3.1.3 and later versions,
 * the key point of divergence is the removal of the b64 claim. Participants using Version 3.1.3 or earlier
 * must support and process correctly signatures that are set to have b64 as false. b64=false indicates that
 * the detached payload is not base64 encoded when calculating the signature.<br>
 *
 * The correct way to verify this version of detached signature with unencoded payload:
 * <b> b64Encode(header).payload.sign( concatenate( b64UrlEncode(header), ".", payload )) </b>
 *
 * @param detachedSignatureValue the detached signature value from the x-jws-signature header
 * @param jwkSet containing the signing keys for this apiClient
 * @param requestPayload the request payload that will not be encoded before validating the detached signature
 * @return true if signature validation is successful, false otherwise
 */
def validateUnencodedPayload(String detachedSignatureValue, JWKSet jwkSet, String requestPayload) {
    Payload payload = new Payload(requestPayload);
    JWSObject parsedJWSObject = JWSObject.parse(detachedSignatureValue, payload)
    JWSHeader jwsHeader = parsedJWSObject.getHeader()

    boolean criticalParamsValid = validateCriticalParameters(jwsHeader)
    logger.debug(SCRIPT_NAME + "Critical headers valid: " + criticalParamsValid)
    if (!criticalParamsValid) {
        return false
    }

    var rsaPublicKey = getRSAKeyFromJwks(jwkSet, jwsHeader)
    RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey, getCriticalHeaderParameters());
    return parsedJWSObject.verify(verifier)
}

/**
 * Validates a request with encoded payload. For version 3.1.4 onward, ASPSPs must not include the
 * b64 claim in the header, and any TPPs using these ASPSPs must do the same. By default b64 will be considered as true
 *
 * The correct way to verify this version of detached signature with encoded payload:
 * <b> b64Encode(header).b64UrlEncode(payload)
 *                      .sign(concatenate(b64UrlEncode(header), ".", b64UrlEncode(payload)))
 * </b>
 *
 * @param detachedSignatureValue the request payload
 * @param jwkSet containing the signing keys for this apiClient
 * @param requestPayload the request payload that will be encoded before validating the detached signature.
 * @return true if signature validation is successful, false otherwise
 */
def validateEncodedPayload(String detachedSignatureValue, JWKSet jwkSet, String requestPayload) {
    JWSObject parsedJWSObject = JWSObject.parse(detachedSignatureValue)
    JWSHeader jwsHeader = parsedJWSObject.getHeader()
    var rsaPublicKey = getRSAKeyFromJwks(jwkSet, jwsHeader)
    return isJwsSignatureValid(detachedSignatureValue, rsaPublicKey, requestPayload, jwsHeader)
}

def getRSAKeyFromJwks(JWKSet jwkSet, JWSHeader jwsHeader) {
    var keyId = jwsHeader.getKeyID()
    logger.debug(SCRIPT_NAME + "Fetching key for keyId: " + keyId)
    JWK jwk = jwkSet.findJwk(keyId);
    if (jwk == null) {
        throw new FailedToLoadJWKException("Failed to find keyId: " + keyId + " in JWKSet");
    }
    return ((RsaJWK) jwk).toRSAPublicKey()
}

/**
 * Encodes the payload for an encoded payload request and performs the signature validation. Defers the validation of
 * critical claims during the process of the signature validation.
 *
 * @param detachedSignatureValue The detached signature header value - x-jws-signature
 * @param rsaPublicKey The JWK used to validate the signature
 * @param requestPayload The request payload or request body. Will be encoded before rebuilding the JWT
 * @param jwsHeader The header of the detached signature
 * @return true if the signatures validation is successful, false otherwise
 */
def isJwsSignatureValid(String detachedSignatureValue,
                        RSAPublicKey rsaPublicKey,
                        String requestPayload,
                        JWSHeader jwsHeader) throws JOSEException, ParseException {
    // Validate crit claims - If this fails stop the flow, no point in continuing with the signature validation.
    boolean criticalParamsValid = validateCriticalParameters(jwsHeader)
    if (!criticalParamsValid) {
        logger.error(SCRIPT_NAME + "Critical params validations failed. Stopping further validations.")
        return false
    }

    //Validate Signature
    logger.debug(SCRIPT_NAME + "JWT from header signature: " + detachedSignatureValue)

    RSASSAVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey, getCriticalHeaderParameters())

    String[] jwtElements = detachedSignatureValue.split("\\.")

    // The payload must be encoded with base64Url
    String rebuiltJwt = jwtElements[0] + "." +
            Base64.getUrlEncoder().withoutPadding().encodeToString(requestPayload.getBytes()) + "." +
            jwtElements[2]

    logger.debug(SCRIPT_NAME + "JWT rebuilt using the request body: " + rebuiltJwt)
    JWSObject jwsObject = JWSObject.parse(rebuiltJwt)

    boolean isValidJws = jwsObject.verify(jwsVerifier)
    logger.debug(SCRIPT_NAME + "Signature validation result: " + isValidJws)

    return isValidJws
}

/**
 * Validates the critical parameters from the detached signature header.
 *
 * @param jwsHeader The header of the detached signature
 * @return true if the critical parameters are valid, false otherwise
 */
def validateCriticalParameters(JWSHeader jwsHeader) {
    logger.debug(SCRIPT_NAME + "Starting validation of critical parameters")

    if (jwsHeader.getAlgorithm() == null || !jwsHeader.getAlgorithm().getName().equals("PS256")) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid algorithm was used: " +
                             jwsHeader.getAlgorithm().getName())
        return false;
    }
    logger.debug(SCRIPT_NAME + "Found valid algorithm!")

    //optional header - only if it's found verify that it's mandatory equal to "JOSE"
    if (jwsHeader.getType() != null && !jwsHeader.getType().getType().equals("JOSE")) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid type detected: " +
                             jwsHeader.getType().getType())
        return false
    }
    logger.debug(SCRIPT_NAME + "Found valid type!")

    def iatClaim = jwsHeader.getCustomParam(IAT_CRIT_CLAIM)
    if (iatClaim == null) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - required claim: " + IAT_CRIT_CLAIM + " not found")
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

    if (jwsHeader.getCustomParam(TAN_CRIT_CLAIM) == null
            || !jwsHeader.getCustomParam(TAN_CRIT_CLAIM).equals(routeArgTrustedAnchor)) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid trusted anchor found: " +
                             jwsHeader.getCustomParam(TAN_CRIT_CLAIM) + " expected: " + routeArgTrustedAnchor)
        return false
    }
    logger.debug(SCRIPT_NAME + "Found valid tan!")


    def issCritClaim = jwsHeader.getCustomParam(ISS_CRIT_CLAIM)
    return validateIssCritClaim(issCritClaim)
}

// Validate the "http://openbanking.org.uk/iss" claim
//
// OB Spec:
// If the issuer is using a signing key lodged with a Trust Anchor, the value is defined by the Trust Anchor and
// should uniquely identify the PSP.
// For example, when using the Open Banking Directory, the value must be:
// - When issued by a TPP, of the form {{org-id}}/{{software-statement-id}},
def validateIssCritClaim(issCritClaim) {
    if (issCritClaim == null) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Missing required header value: " + ISS_CRIT_CLAIM)
        return false
    }
    def apiClient = apiClient()
    def orgId = apiClient.getOrganisation().id()
    def softwareStatementId = apiClient.getSoftwareId()
    def expectedIssuerValue = orgId + "/" + softwareStatementId
    if (expectedIssuerValue != issCritClaim) {
        logger.error(SCRIPT_NAME + "Invalid " + ISS_CRIT_CLAIM +
                             " value, expected: " + expectedIssuerValue +
                             " actual: " + issCritClaim)
        return false
    }
    logger.debug(SCRIPT_NAME + ISS_CRIT_CLAIM + " is valid")
    return true
}

def apiClient() {
    def apiClient = attributes.apiClient
    if (apiClient == null) {
        throw new IllegalStateException("Route is configured incorrectly, " + SCRIPT_NAME +
                                                "requires apiClient context attribute")
    }
    return apiClient
}

/**
 * Builds a Set of expected critical claims. These must be ignored during the signature validation, and validated
 * separately.
 * @return Set of crit claims
 */
def getCriticalHeaderParameters() {
    Set<String> criticalParameters = new HashSet<String>()
    criticalParameters.add(IAT_CRIT_CLAIM)
    criticalParameters.add(ISS_CRIT_CLAIM)
    criticalParameters.add(TAN_CRIT_CLAIM)
    return criticalParameters
}


