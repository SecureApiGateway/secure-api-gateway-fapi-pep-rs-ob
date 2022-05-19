import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import groovy.json.JsonSlurper
import org.bouncycastle.asn1.x500.X500Name
import org.forgerock.http.protocol.*
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*

import java.text.ParseException

import static org.forgerock.util.promise.Promises.newResultPromise

/**
 Subject to waiver for earlier versions as per
 https://openbanking.atlassian.net/wiki/spaces/DZ/pages/1112670669/W007

 If ASPSPs are still using v3.1.3 or earlier, they must support the parameter b64 to be false,
 and any TPPs using these ASPSPs must do the same.

 If ASPSPs have updated to v3.1.4 or later, they must not include the b64 claim in the header,
 and any TPPs using these ASPSPs must do the same.
 */

SCRIPT_NAME = "[ProcessDetachedSig] - "

def method = request.method
if (method != "POST") {
    //This script should be executed only if it is a POST request
    logger.debug(SCRIPT_NAME + "Skipping the filter because the method is not POST, the method is " + method)
    return next.handle(context, request)
}

IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"

response = new Response(Status.BAD_REQUEST)
response.headers['Content-Type'] = "application/json"

// Parse api version from the request path
logger.debug(SCRIPT_NAME + "request.uri.path: " + request.uri.path)
String apiVersionRegex = "(v(\\d+.)?(\\d+.)?(\\*|\\d+))"

def match = (request.uri.path =~ apiVersionRegex)
def apiVersion = "";
if (match.find()) {
    apiVersion = match.group(1)
    logger.debug(SCRIPT_NAME + "API version: " + apiVersion)
} else {
    message = "Can't parse API version for inbound request"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

logger.debug(SCRIPT_NAME + "Building JWT from detached header")

def header = request.headers.get(routeArgHeaderName)

if (header == null) {
    message = "No detached signature header on inbound request " + routeArgHeaderName
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String detachedSig = header.firstValue.toString()

logger.debug(SCRIPT_NAME + "Inbound detached signature: " + detachedSig)
String[] sigElements = detachedSig.split("\\.")

if (sigElements.length != 3) {
    message = "Wrong number of dots on inbound detached signature " + sigElements.length
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String jwtHeader = sigElements[0]

// Check JWT header for b64 claim
// If claim is present, and API version > 3.1.3 then reject
// If claim is present, and is set to false, and API < 3.1.4 then accept and validate as non base64 payload

String headerJson = new String(jwtHeader.decodeBase64Url())
logger.debug(SCRIPT_NAME + "Got JWT header: " + headerJson)
JsonSlurper slurper = new JsonSlurper()
def headerObj = slurper.parseText(headerJson)

//Get the API client from the oauth2 token context. This will be used to query the IDM API client managed object.
def tppClientId
if (routeArgClientIdFieldName == "client_id") {
    tppClientId = contexts.oauth2.accessToken.info.client_id
} else {
    tppClientId = contexts.oauth2.accessToken.info.aud
}

if (tppClientId == null) {
    message = "Cannot obtain TPP client id from the access token"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

logger.debug(SCRIPT_NAME + "TPP client id: " + tppClientId)

if (['v3.0', 'v3.1.0', 'v3.1.1', 'v3.1.2', 'v3.1.3'].contains(apiVersion)) {
    //Processing pre v3.1.4 requests
    if (headerObj.b64 == null) {
        message = "B64 header must be presented in JWT header before v3.1.3"
        logger.error(SCRIPT_NAME + message)
        return getSignatureValidationErrorResponse()
    } else if (headerObj.b64 != false) {
        message = "B64 header must be false in JWT header before v3.1.3"
        logger.error(SCRIPT_NAME + message)
        return getSignatureValidationErrorResponse()
    } else {
        String jwtPayload = request.entity.getString()

        Request apiClientRequest = new Request();
        apiClientRequest.setMethod('GET');
        apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + tppClientId)

        //Get API client details in order to obtain the jwks_uri required for the signature validation
        return http.send(apiClientRequest).thenAsync(apiClientResponse -> {
            def responseBody = apiClientResponse.getEntity().getJson();
            def responseStatus = apiClientResponse.getStatus();
            logger.debug(SCRIPT_NAME + "Get API client response status: " + responseStatus)

            def jwks_uri = responseBody.get("jwksUri");
            logger.debug(SCRIPT_NAME + "API client jwks_uri: " + jwks_uri)

            try {
                logger.debug(SCRIPT_NAME + "Processing Unencoded payload request")
                if (!validateUnencodedPayload(detachedSig, jwks_uri, jwtPayload)) {
                    return newResultPromise(getSignatureValidationErrorResponse())
                }
            }
            catch (java.lang.Exception e) {
                logger.error(SCRIPT_NAME + "Exception validating the detached jws: " + e);
                return newResultPromise(getSignatureValidationErrorResponse())
            }

            logger.debug(SCRIPT_NAME + "Detached signature verified successfully against unencoded payload!")
            return next.handle(context, request)
        })
    }
} else {
    //Processing post v3.1.4 requests
    if (headerObj.b64 != null) {
        message = "B64 header not permitted in JWT header after v3.1.3"
        logger.error(SCRIPT_NAME + message)
        return getSignatureValidationErrorResponse()
    }

    String jwtPayload = request.entity.getString()

    Request apiClientRequest = new Request();
    apiClientRequest.setMethod('GET');
    apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + tppClientId)

    //Get API client details in order to obtain the jwks_uri required for the signature validation
    return http.send(apiClientRequest).thenAsync(apiClientResponse -> {
        def responseBody = apiClientResponse.getEntity().getJson();
        def responseStatus = apiClientResponse.getStatus();
        logger.debug(SCRIPT_NAME + "Get API client response status: " + responseStatus)
        def jwks_uri = responseBody.get("jwksUri");
        logger.debug(SCRIPT_NAME + "API client jwks_uri: " + jwks_uri)

        try {
            logger.debug(SCRIPT_NAME + "Standard base64 encoded payload for detached sig")
            if (!validateEncodedPayload(detachedSig, jwks_uri, jwtPayload)) {
                return newResultPromise(getSignatureValidationErrorResponse())
            }
        }
        catch (java.lang.Exception e) {
            logger.error(SCRIPT_NAME + "Exception validating the detached jws: " + e);
            return newResultPromise(getSignatureValidationErrorResponse())
        }
        logger.debug(SCRIPT_NAME + "Detached signature validation was succesful with encoded payload!")
        return next.handle(context, request)
    })
}

next.handle(context, request)

// End script execution - Start method definitions

/**
 * Validates a request with unencoded payload. Between Version 3.1.3 and later versions,
 * the key point of divergence is the removal of the b64 claim. Participants using Version 3.1.3 or earlier
 * must support and process correctly signatures that are set to have b64 as false. b64=false indicates that
 * the detached payload is not base64 encoded when calculating the signature.<br>
 *
 * The correct way to verify this version of detached signature with unencoded payload:
 * <b> b64Encode(header).payload.sign( concatenate( b64UrlEncode(header), ".", payload )) </b>
 *
 * @param jws the detached signature from the x-jws-signature header
 * @param payload the request payload that will not be encoded before validating the detched signature
 * @param routeArgJwkUrl the API client JWKS_URI
 * @return true if signature validation is successful, false otherwise
 */
def validateUnencodedPayload(String jws, String routeArgJwkUrl, String payload) {
    Payload detachedPayload = new Payload(payload);
    JWSObject parsedJWSObject = JWSObject.parse(jws, detachedPayload);
    JWSHeader jwsHeader = parsedJWSObject.getHeader();

    boolean criticalParamsValid = validateCriticalParameters(jwsHeader)
    logger.debug(SCRIPT_NAME + "Critical headers valid: " + criticalParamsValid)
    if (criticalParamsValid == false) {
        return false
    }

    RSAKey rsaPublicJWK = getRSAKeyFromJwks(routeArgJwkUrl, jwsHeader)

    if (rsaPublicJWK == null) {
        return false;
    }

    RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicJWK.toRSAPublicKey(), getCriticalHeaderParameters());
    return parsedJWSObject.verify(verifier)
}

/**
 * Validates a request with encoded payload. For version 3.1.4 onward, ASPSPs must not include the
 * b64 claim in the header, and any TPPs using these ASPSPs must do the same. By defaut b64 will be considered as true
 *
 * The correct way to verify this version of detached signature with encoded payload:
 * <b> b64Encode(header).b64UrlEncode(payload).sign( concatenate( b64UrlEncode(header), ".", b64UrlEncode(payload) ) ) </b>
 *
 * @param payload the request payload
 * @param routeArgJwkUrl the API client JWKS_URI
 * @param jwtPayload the request payload that will be encoded before validating the detached signature.
 * @return true if signature validation is successful, false otherwise
 */
def validateEncodedPayload(String payload, String routeArgJwkUrl, String jwtPayload) {
    JWSObject parsedJWSObject = JWSObject.parse(payload);
    JWSHeader jwsHeader = parsedJWSObject.getHeader();

    RSAKey rsaPublicJWK = getRSAKeyFromJwks(routeArgJwkUrl, jwsHeader)
    if (rsaPublicJWK == null) {
        return false;
    }
    return isJwsValid(payload, rsaPublicJWK, jwtPayload, jwsHeader);
}

/**
 * Given a JWKS_URI and a JWS header, the method will load the JWKS_URI and will return the first matching public key,
 * if any are found. They key will be initialized and returned as RSAKey
 *
 * @param routeArgJwkUrl the API client JWKS_URI
 * @param jwsHeader the JWS header for which we need to find the public key
 * @return the RSAKey that matches the kid from the JWS header given
 */
def getRSAKeyFromJwks(String routeArgJwkUrl, JWSHeader jwsHeader) {
    JWKSet jwkSet
    try {
        jwkSet = JWKSet.load(new URL(routeArgJwkUrl));
    }
    catch (java.lang.Exception e) {
        logger.error(SCRIPT_NAME + "Exception getting JWK set: " + e);
        return null;
    }

    logger.debug(SCRIPT_NAME + "jwkSet: " + jwkSet.toString())

    List<JWK> matches = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader))
            .select(jwkSet);

    if (matches.size() != 1) {
        logger.error(SCRIPT_NAME + "Unexpected number of matching JWKs: " + matches.size());
        return null
    }

    RSAKey rsaPublicJWK = (RSAKey) matches.get(0).toPublicJWK();
    return rsaPublicJWK;
}

/**
 * Encodes the payload for an encoded payload request and performs the signature validation. Defers the validation of
 * critical claims during the process of the signature validation.
 *
 * @param jwt The detached signature header value - x-jws-signature
 * @param jwk The JWK used to validate the signature
 * @param jwtPayload The request payload or request body. Will be encoded before rebuilding the JWT
 * @param jwsHeader The header of the detached signature
 * @return true if the signatures validation is successful, false otherwise
 */
def isJwsValid(String jwt, JWK jwk, String jwtPayload, JWSHeader jwsHeader) throws JOSEException, ParseException {
    // Validate crit claims - If this fails stop the flow, no point in continuing with the signature validation.
    boolean criticalParamsValid = validateCriticalParameters(jwsHeader);
    if (!criticalParamsValid) {
        logger.error(SCRIPT_NAME + "Critical params validations failed. Stopping further validations.")
        return false
    }

    //Validate Signature
    logger.debug(SCRIPT_NAME + "JWT from header signature: " + jwt)

    RSASSAVerifier jwsVerifier = new RSASSAVerifier(jwk.toRSAKey().toRSAPublicKey(),
            getCriticalHeaderParameters());

    String[] jwtElements = jwt.split("\\.")

    String rebuiltJwt = jwtElements[0] + "." + Base64.getEncoder().withoutPadding().encodeToString(jwtPayload.getBytes()) + "." + jwtElements[2]

    logger.debug(SCRIPT_NAME + "JWT rebuilt using the request body: " + rebuiltJwt)
    JWSObject jwsObject = JWSObject.parse(rebuiltJwt);

    boolean isValidJws = jwsObject.verify(jwsVerifier);
    logger.debug(SCRIPT_NAME + "Signature validation result: " + isValidJws)

    return isValidJws;
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
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid algorithm was used: " + jwsHeader.getAlgorithm().getName())
        return false;
    }
    logger.debug(SCRIPT_NAME + "Found valid algorithm!")

    //optional header - only if it's found verify that it's mandatory equal to "JOSE"
    if (jwsHeader.getType() != null && !jwsHeader.getType().getType().equals("JOSE")) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid type detected: " + jwsHeader.getType().getType())
        return false;
    }
    logger.debug(SCRIPT_NAME + "Found valid type!")

    long currentTimestamp = System.currentTimeMillis() / 1000;
    if (jwsHeader.getCustomParam(IAT_CRIT_CLAIM) == null || !(Long.valueOf(jwsHeader.getCustomParam(IAT_CRIT_CLAIM)) < currentTimestamp)) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid issued at timestamp - value from JWT: " + jwsHeader.getCustomParam(IAT_CRIT_CLAIM) + " and current timestamp: " + currentTimestamp)
        return false;
    }
    logger.debug(SCRIPT_NAME + "Found valid iat!")

    if (jwsHeader.getCustomParam(TAN_CRIT_CLAIM) == null || !jwsHeader.getCustomParam(TAN_CRIT_CLAIM).equals(routeArgTrustedAnchor)) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid trusted anchor found: " + jwsHeader.getCustomParam(TAN_CRIT_CLAIM) + " expected: " + routeArgTrustedAnchor)
        return false;
    }
    logger.debug(SCRIPT_NAME + "Found valid tan!")

    X500Name jwtHeaderSubject = new X500Name(jwsHeader.getCustomParam(ISS_CRIT_CLAIM))
    logger.debug(SCRIPT_NAME + "Initialized jwtHeaderSubject: " + jwtHeaderSubject)

    X500Name routeSubjectDn = new X500Name(attributes.clientCertificate.subjectDN.toString())
    logger.debug(SCRIPT_NAME + "Initialized routeSubjectDn: " + routeSubjectDn)


    if (!routeSubjectDn.equals(jwtHeaderSubject)) {
        logger.error(SCRIPT_NAME + "Could not validate detached JWT - Comparison of subject dns failed")
        return false;
    }
    return true;
}

/**
 * Builds a Set of expected critical claims. These must be ignored during the signature validation, and validated
 * separately.
 * @return Set of crit claims
 */
def getCriticalHeaderParameters() {
    Set<String> criticalParameters = new HashSet<String>()
    criticalParameters.add(IAT_CRIT_CLAIM);
    criticalParameters.add(ISS_CRIT_CLAIM);
    criticalParameters.add(TAN_CRIT_CLAIM);
    return criticalParameters;
}

/**
 * Builds the signature validation failur error response
 * @return error response
 */
def getSignatureValidationErrorResponse() {
    message = "Signature validation failed"
    logger.error(SCRIPT_NAME + message)
    Response response = new Response(Status.UNAUTHORIZED)
    response.setEntity("{ \"error\":\"" + message + "\"}")
    return response;
}
