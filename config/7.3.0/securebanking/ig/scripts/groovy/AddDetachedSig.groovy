import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.http.protocol.Status.OK
import static org.forgerock.http.protocol.Status.INTERNAL_SERVER_ERROR
import static org.forgerock.secrets.Purpose.purposeOf

import org.forgerock.secrets.keys.SigningKey
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.exceptions.InvalidJwtException
import org.forgerock.secrets.Purpose
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.http.protocol.Status

import org.forgerock.util.promise.NeverThrowsException
import org.forgerock.json.JsonValue

/**
 * Add detached signature to HTTP response
 *
 * Detached signature is signed JWT with response entity as payload
 * JWT is added as response header, with payload removed
 *
 * Can be replaced with JwtBuilderFilter if/when it can be used as a response filter
 *
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[AddDetachedSig] (" + fapiInteractionId + ") - "

IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"

return filter(context, request, next)

/**
 * Filter implementation to add the detached signature.
 * @param context the Context
 * @param request the request
 * @param next the next Handler
 * @return Promise of a Response containing the API client
 */
Promise<Response, NeverThrowsException> filter(final Context context,
                                               final Request request,
                                               final Handler next) {
    return next.handle(context, request).thenOnResult({ response ->
        logger.debug(SCRIPT_NAME + "Running... routeArgSecretId: {}, routeArgKid: {}", routeArgSecretId, routeArgKid)
        return getJwtClaimsSet(response)
                .thenAsync(jwtClaimSet -> buildEncodedJwt(jwtClaimSet),
                      exception -> newResponsePromise(fail(INTERNAL_SERVER_ERROR, exception.getMessage())))
                .then(encodedJwt -> addDetachedSignature(encodedJwt, response),
                      exception -> {
                          return fail(INTERNAL_SERVER_ERROR, "Error creating signature JWT")
                      })
                .thenCatch(exception -> fail(INTERNAL_SERVER_ERROR, exception.getMessage()))
    })
}

private Promise<JwtClaimsSet, Exception> getJwtClaimsSet(Response response) {
    if (response.getEntity().isRawContentEmpty()) {
        // We get content empty on submit file payment API
        logger.debug("Response entity has raw content")
        return newResultPromise(new JwtClaimsSet())
    }
    return response.getEntity()
                   .getJsonAsync()
                   .then(jsonContent -> new JsonValue(jsonContent).expect(Map.class))
                   .then(jsonContent -> new JwtClaimsSet(jsonContent.asMap()),
                         exception -> {
                             throw new IOException("Evaluation response has malformed response JSON");
                         })
}

private Promise<String, Exception> buildEncodedJwt(JwtClaimsSet jwtClaimsSet) {
    logger.debug(SCRIPT_NAME + "Building encoded JWT for claims set: {}", jwtClaimsSet)
    Purpose<SigningKey> purpose = new JsonValue(routeArgSecretId).as(purposeOf(SigningKey.class))
    SigningManager signingManager = new SigningManager(routeArgSecretsProvider)
    return signingManager.newSigningHandler(purpose).then({ signingHandler ->
        logger.debug(SCRIPT_NAME + "Building of the JWT started")
        List<String> critClaims = List.of(IAT_CRIT_CLAIM, ISS_CRIT_CLAIM, TAN_CRIT_CLAIM);
        JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(routeArgAlgorithm)
        logger.debug(SCRIPT_NAME + "Algorithm initialised: " + signAlgorithm)
        String encodedJwt = new JwtBuilderFactory()
                .jws(signingHandler)
                .headers()
                .alg(signAlgorithm)
                .kid(routeArgKid)
                .header(IAT_CRIT_CLAIM, System.currentTimeMillis() / 1000)
                // For an ASPSP the ISS_CRIT_CLAIM is the OB Issued orgId
                .header(ISS_CRIT_CLAIM, obAspspOrgId)
                .header(TAN_CRIT_CLAIM, routeArgTrustedAnchor)
                .crit(critClaims)
                .done()
                .claims(jwtClaimsSet)
                .build()
        return encodedJwt
    })
}

private Response addDetachedSignature(String encodedJwt, Response response) {
    logger.debug(SCRIPT_NAME + "Adding detached signature - encodedJwt {}", encodedJwt)
    String[] jwtElements = encodedJwt.split("\\.")
    if (jwtElements.length != 3) {
        message = "Wrong number of dots on outbound detached signature"
        logger.error(SCRIPT_NAME + message)
        throw new InvalidJwtException(message) as Throwable
    }
    // Create JWT with detached sig
    String detachedSig = "%s..%s".formatted(jwtElements[0], jwtElements[2])
    logger.debug(SCRIPT_NAME + "Adding detached signature [{}]", detachedSig)
    response.getHeaders().add(routeArgHeaderName, detachedSig);
    return response
}

private Response fail(Status errorStatus, String errorMessage) {
    Response response = new Response(OK)
    response.headers['Content-Type'] = "application/json"
    response.status = errorStatus
    response.entity = json(object(field("error", errorMessage)))
    return response
}