import groovy.json.JsonSlurper
import org.forgerock.http.protocol.Status
import org.forgerock.json.resource.Response

import static org.forgerock.util.promise.Promises.newResultPromise
import static org.forgerock.util.promise.Promises.when
import org.forgerock.http.protocol.*
/**
 * Sign each event from the response payload received from Test Facility Bank using the Signer provided by the Heap
 *
 * An Event Notification message needs to be structured as JWT
 * aligned with Security Event Token standard (SET) (https://datatracker.ietf.org/doc/html/rfc8417)
 *
 * Event Notifications messages must be signed for non-repudiation
 */
/*
Response from RS
{
    "moreAvailable": false,
    "sets": {
        "6589a939-c6b2-4c5b-8ce3-b86ab13f2e49": "{\"aud\":\"7umx5nTR33811QyQfi\",\"events\":{\"urn:uk:org:openbanking:events:resource-update\":{\"subject\":{\"subject_type\":\"http://openbanking.org.uk/rid_http://openbanking.org.uk/rty\",\"http://openbanking.org.uk/rid\":\"pmt-7290-001\",\"http://openbanking.org.uk/rty\":\"domestic-payment\",\"http://openbanking.org.uk/rlk\":[{\"version\":\"v3.1.10\",\"link\":\"https://examplebank.com/api/open-banking/v3.1.0/pisp/domestic-payments/pmt-7290-001\"},{\"version\":\"v1.1\",\"link\":\"https://examplebank.com/api/open-banking/v1.1/payment-submissions/pmt-7290-001\"}]}}},\"iat\":1516239022,\"iss\":\"https://examplebank.com/\",\"jti\":\"6589a939-c6b2-4c5b-8ce3-b86ab13f2e49\",\"sub\":\"https://examplebank.com/api/open-banking/v3.1.10/pisp/domestic-payments/pmt-7290-001\",\"toe\":1516239022,\"txn\":\"dfc51628-3479-4b81-ad60-210b43d02306\"}"
    }
}

Response to the TPP
{
    "moreAvailable": false,
    "sets": {
        "6589a939-c6b2-4c5b-8ce3-b86ab13f2e49": "eyJ0eXAiOiJKV1QiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTY5MjM3MzAxNy4zNzUsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiY3JpdCI6WyJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvaXNzIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay90YW4iXSwia2lkIjoieGNKZVZ5dFRrRkwyMWxISVVWa0FkNlFWaTRNIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDQxUkVBQVkiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImI0NjBhMDdjLTQ5NjItNDNkMS04NWVlLTlkYzEwZmJiOGY2YyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZWJhbmsuY29tL2FwaS9vcGVuLWJhbmtpbmcvdjMuMC9waXNwL2RvbWVzdGljLXBheW1lbnRzL3BtdC03MjkwLTAwMyIsImF1ZCI6Ijd1bXg1blRSMzM4MTFReVFmaSIsInR4biI6ImRmYzUxNjI4LTM0NzktNGI4MS1hZDYwLTIxMGI0M2QwMjMwNiIsInRvZSI6MTUxNjIzOTAyMiwiZXZlbnRzIjp7InVybjp1azpvcmc6b3BlbmJhbmtpbmc6ZXZlbnRzOnJlc291cmNlLXVwZGF0ZSI6eyJzdWJqZWN0Ijp7InN1YmplY3RfdHlwZSI6Imh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcmlkX2h0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcnR5IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9yaWQiOiJwbXQtNzI5MC0wMDMiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3J0eSI6ImRvbWVzdGljLXBheW1lbnQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3JsayI6W3sidmVyc2lvbiI6InYzLjAiLCJsaW5rIjoiaHR0cHM6Ly9leGFtcGxlYmFuay5jb20vYXBpL29wZW4tYmFua2luZy92My4wL3Bpc3AvZG9tZXN0aWMtcGF5bWVudHMvcG10LTcyOTAtMDAzIn0seyJ2ZXJzaW9uIjoidjEuMSIsImxpbmsiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS9hcGkvb3Blbi1iYW5raW5nL3YxLjEvcGF5bWVudC1zdWJtaXNzaW9ucy9wbXQtNzI5MC0wMDMifV19fX19.nf4oYEg6OINDEwHBDtdo_62YMWYckybRsv7vnzKLfJpNqm-bI02An7sOZSfhcJrs-nURv_Fo3_wydLal1pXEwgwhUe4-5IvtdqHfYnbzTv9XHXSNtiJIvvT6XzrPtRPyc79G7M_zSd3GMlTOkmKTeOu7F12SylHWXpff0MMu45A2NvcUat6BIqA09KFs9_3dLA9eX4Ng26oBIRYJqe8owKm2m-hvIN6SWBAUiFxIzmXfpM7GPo3tU2zc8NErDydvZt6TfDKDvbWGQiawO4XEdLRDg0YsTZv-N6bv99lDEvv1nqO-xKTaH_G9JSKLrf9KH7ou1cmli1wDh28bE2Fi9Q"
    }
}

Error response example:
{
    "Code": "500",
    "Id": "ede36b552dc951d9836a127f16a7c033",
    "Message": "[Status: 500 Internal Server Error]",
    "Errors": [
        {
            "ErrorCode": "UK.OBIE.UnexpectedError",
            "Message": "Internal error [Unknown Signing Algorithm]"
        }
    ]
}

Validate signature
- You can validate the JWT SET signature in: https://jwt.davetonge.co.uk/
- Copy a JWT 'set' value and paste in the web page.
- JWKs URL endpoint to validate the signature: https://keystore.openbankingtest.org.uk/0015800001041REAAY/0015800001041REAAY.jwks
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[SignEventsResponse] (" + fapiInteractionId + ") - "

Map<String, Object> critClaims = Map.of(
        "http://openbanking.org.uk/iat", System.currentTimeMillis() / 1000,
        "http://openbanking.org.uk/iss", aspspOrgId,
        "http://openbanking.org.uk/tan", "openbanking.org.uk")

next.handle(context, request).thenAsync({ response ->
    logger.debug("{} Running...", SCRIPT_NAME)

    Status status = response.getStatus()

    if (status.isClientError() || status.isServerError()) {
        return newResultPromise(response)
    }

    var rsResponseBody = response.getEntity().getJson()

    Map<String, String> sets = rsResponseBody.sets

    def slurper = new JsonSlurper()

    /* No blocking Async loop call (returns a promise):
     * - Compute the signature for each SET (Signed Event Token) retrieved from the Test utility bank (RS) response in a loop
     * - When all promises have been succeeded then process the result (List<Map<jti, signedJwt>)
     *   - Overrides each SET json plain value received from RS with the signedJwt
     *   - Overrides the response entity with the new signed SETs
     *   - Returns the modified response to the handler
     */
    return when(sets.collect(set -> {
        Map payloadMap = slurper.parseText(set.value)
        return signer.sign(payloadMap, critClaims)
                .then(signedJwt -> {
                    return Map.entry(set.key, signedJwt)
                })
    })).then(signedJwtResults -> {
        signedJwtResults.forEach {
            entry -> rsResponseBody.sets[entry.key] = entry.value
        }
        response.entity = rsResponseBody
        logger.debug("{} Final json {}", SCRIPT_NAME, rsResponseBody)
        return response
    }, sapiJwsSignerException -> {
        logger.error("{} Signature fails: {}", SCRIPT_NAME, sapiJwsSignerException.getMessage())
        response.status = Status.INTERNAL_SERVER_ERROR
        response.entity = "{ \"error\":\"" + sapiJwsSignerException.getMessage() + "\"}"
        return newResultPromise(response)
    })
})