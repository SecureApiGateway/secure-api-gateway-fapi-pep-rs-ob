import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.http.util.Json.readJson
import static org.forgerock.util.promise.Promises.when

import org.forgerock.http.protocol.Status
import org.forgerock.json.JsonValue
import org.forgerock.json.resource.Response
import org.forgerock.util.promise.NeverThrowsException
import com.forgerock.sapi.gateway.ob.jws.signer.JwsSignerException

/**
 * Sign each event from the response payload received from Test Facility Bank using the Signer provided by the Heap.
 * Event Notifications messages must be signed for non-repudiation.
 *
 * An Event Notification message needs to be structured as a JWT aligned with the
 * <a href="Security Event Token standard (SET)">https://datatracker.ietf.org/doc/html/rfc8417</a> specification.
 *
 * Example response from RS:
 * {
 *     "moreAvailable": false,
 *     "sets": {
 *         "6589a939-c6b2-4c5b-8ce3-b86ab13f2e49": "{\"aud\":\"7umx5nTR33811QyQfi\",\"events\":{\"urn:uk:org:openbanking:events:resource-update\":{\"subject\":{\"subject_type\":\"http://openbanking.org.uk/rid_http://openbanking.org.uk/rty\",\"http://openbanking.org.uk/rid\":\"pmt-7290-001\",\"http://openbanking.org.uk/rty\":\"domestic-payment\",\"http://openbanking.org.uk/rlk\":[{\"version\":\"v3.1.10\",\"link\":\"https://examplebank.com/api/open-banking/v3.1.0/pisp/domestic-payments/pmt-7290-001\"},{\"version\":\"v1.1\",\"link\":\"https://examplebank.com/api/open-banking/v1.1/payment-submissions/pmt-7290-001\"}]}}},\"iat\":1516239022,\"iss\":\"https://examplebank.com/\",\"jti\":\"6589a939-c6b2-4c5b-8ce3-b86ab13f2e49\",\"sub\":\"https://examplebank.com/api/open-banking/v3.1.10/pisp/domestic-payments/pmt-7290-001\",\"toe\":1516239022,\"txn\":\"dfc51628-3479-4b81-ad60-210b43d02306\"}"
 *     }
 * }
 *
 * Example response to the TPP:
 * {
 *     "moreAvailable": false,
 *     "sets": {
 *         "6589a939-c6b2-4c5b-8ce3-b86ab13f2e49": "eyJ0eXAiOiJKV1QiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTY5MjM3MzAxNy4zNzUsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiY3JpdCI6WyJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvaXNzIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay90YW4iXSwia2lkIjoieGNKZVZ5dFRrRkwyMWxISVVWa0FkNlFWaTRNIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDQxUkVBQVkiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImI0NjBhMDdjLTQ5NjItNDNkMS04NWVlLTlkYzEwZmJiOGY2YyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZWJhbmsuY29tL2FwaS9vcGVuLWJhbmtpbmcvdjMuMC9waXNwL2RvbWVzdGljLXBheW1lbnRzL3BtdC03MjkwLTAwMyIsImF1ZCI6Ijd1bXg1blRSMzM4MTFReVFmaSIsInR4biI6ImRmYzUxNjI4LTM0NzktNGI4MS1hZDYwLTIxMGI0M2QwMjMwNiIsInRvZSI6MTUxNjIzOTAyMiwiZXZlbnRzIjp7InVybjp1azpvcmc6b3BlbmJhbmtpbmc6ZXZlbnRzOnJlc291cmNlLXVwZGF0ZSI6eyJzdWJqZWN0Ijp7InN1YmplY3RfdHlwZSI6Imh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcmlkX2h0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcnR5IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9yaWQiOiJwbXQtNzI5MC0wMDMiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3J0eSI6ImRvbWVzdGljLXBheW1lbnQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3JsayI6W3sidmVyc2lvbiI6InYzLjAiLCJsaW5rIjoiaHR0cHM6Ly9leGFtcGxlYmFuay5jb20vYXBpL29wZW4tYmFua2luZy92My4wL3Bpc3AvZG9tZXN0aWMtcGF5bWVudHMvcG10LTcyOTAtMDAzIn0seyJ2ZXJzaW9uIjoidjEuMSIsImxpbmsiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS9hcGkvb3Blbi1iYW5raW5nL3YxLjEvcGF5bWVudC1zdWJtaXNzaW9ucy9wbXQtNzI5MC0wMDMifV19fX19.nf4oYEg6OINDEwHBDtdo_62YMWYckybRsv7vnzKLfJpNqm-bI02An7sOZSfhcJrs-nURv_Fo3_wydLal1pXEwgwhUe4-5IvtdqHfYnbzTv9XHXSNtiJIvvT6XzrPtRPyc79G7M_zSd3GMlTOkmKTeOu7F12SylHWXpff0MMu45A2NvcUat6BIqA09KFs9_3dLA9eX4Ng26oBIRYJqe8owKm2m-hvIN6SWBAUiFxIzmXfpM7GPo3tU2zc8NErDydvZt6TfDKDvbWGQiawO4XEdLRDg0YsTZv-N6bv99lDEvv1nqO-xKTaH_G9JSKLrf9KH7ou1cmli1wDh28bE2Fi9Q"
 *      }
 * }
 *
 * Example error response:
 * {
 *     "Code": "500",
 *     "Id": "ede36b552dc951d9836a127f16a7c033",
 *     "Message": "[Status: 500 Internal Server Error]",
 *     "Errors": [
 *         {
 *          "ErrorCode": "UK.OBIE.UnexpectedError",
 *          "Message": "Internal error [Unknown Signing Algorithm]"
 *        }
 *    ]
 * }
 */

/*  Validating the signature:
 * - You can validate the JWT SET signature in: https://jwt.davetonge.co.uk/
 * - Copy a JWT 'set' value and paste in the web page.
 * - JWKs URL endpoint to validate the signature: https://keystore.openbankingtest.org.uk/0015800001041REAAY/0015800001041REAAY.jwks
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[SignEventsResponse] (" + fapiInteractionId + ") - "

CRITICAL_CLAIMS = Map.of(
        "http://openbanking.org.uk/iat", System.currentTimeMillis() / 1000,
        "http://openbanking.org.uk/iss", aspspOrgId,
        "http://openbanking.org.uk/tan", "openbanking.org.uk")

// Sign the response security event token payload
return filter(context, request, next)

/**
 * Filter implementation to sign the security event token response payload.
 * @param context the Context
 * @param request the request
 * @param next the next Handler
 * @return Promise of a Response containing the signed event tokens
 */
Promise<Response, NeverThrowsException> filter(final Context context,
                                               final Request request,
                                               final Handler next) {
    logger.debug("{} Running...", SCRIPT_NAME)
    next.handle(context, request).thenAsync({ response ->
        Status status = response.getStatus()
        if (status.isClientError() || status.isServerError()) {
            return newResponsePromise(response)
        }
        return response.getEntity()
                       .getJsonAsync()
                       .then(jsonContent -> new JsonValue(jsonContent))
                       .then(jsonContent -> jsonContent.get("sets").asMap(Object.class))
                       .thenAsync(sets -> {
                           logger.debug("{} Processing SETs {}", SCRIPT_NAME, sets)
                           return signSecurityEventTokens(sets)
                       })
                       .then(ignored -> response,
                             jwsSignerException -> {
                                 logger.error("{} Signature failed: {}", SCRIPT_NAME, jwsSignerException.getMessage())
                                 response.status = Status.INTERNAL_SERVER_ERROR
                                 response.entity = json(object(field("error", jwsSignerException.getMessage())))
                                 return response
                             })
    })
}

private Promise<Void, JwsSignerException> signSecurityEventTokens(Map<String, Object> securityEventTokens) {
    /* No blocking Async loop call (returns a promise):
     * - Compute the signature for each SET (Security Event Token) retrieved from the Test utility bank (RS) response
     *   in a loop.
     * - When all promises have been succeeded then process the result (List<Map<jti, signedJwt>):
     *   - Overrides each SET json plain value received from RS with the signedJwt
     *   - This effectively replaces in-place the response entity SETs with the new signed SETs
     */
    return when(securityEventTokens.collect(token -> {
        // Transform `set` as is provided as JSON String representation
        Map tokenPayload = readJson(token.value)
        return signer.sign(tokenPayload, CRITICAL_CLAIMS)
                     .then(signedJwt -> {
                         return Map.entry(token.key, signedJwt)
                     })
            }))
            .thenOnResult(signedSetJwts -> {
                // Rewrite the response security event token(s) as the signed JWT representation
                signedSetJwts.forEach {
                    entry -> securityEventTokens.put(entry.key, entry.value)
                }
                logger.debug("{} Processed signed SETs {}", SCRIPT_NAME, securityEventTokens)
            })
            .thenDiscardResult()
}