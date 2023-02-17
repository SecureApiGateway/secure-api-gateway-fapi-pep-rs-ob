/*
 * Script to check the idempotency
 */

import groovy.json.JsonOutput
import java.time.Instant

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[CheckIdempotencyKey] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

// response object
responseCheck = new Response(Status.OK)
responseCheck.headers['Content-Type'] = "application/json"

String idempotencyKeyHeaderValue = request.getHeaders().getFirst("x-idempotency-key")
logger.debug(SCRIPT_NAME + " idempotency key: " + idempotencyKeyHeaderValue)

def method = request.method

// Only check when post
switch (method.toUpperCase()) {
    case "POST":
        if (idempotencyKeyHeaderValue == null || idempotencyKeyHeaderValue == "") {
            message = "Failed to get create the resource, 'x-idempotency-key' header / value expected"
            logger.error(SCRIPT_NAME + message)
            responseCheck.status = Status.BAD_REQUEST
            responseCheck.entity = "{ \"error\":\"" + message + "\"}"
            return newResultPromise(responseCheck)
            // the idempotencyKey size must be at most 40 characters
        } else if(idempotencyKeyHeaderValue.length() > 40){
            message = "Failed to get create the resource, 'x-idempotency-key' size exceeded, the size must be at most 40 characters"
            logger.error(SCRIPT_NAME + message)
            responseCheck.status = Status.BAD_REQUEST
            responseCheck.entity = "{ \"error\":\"" + message + "\"}"
            return newResultPromise(responseCheck)
        }

        // prepare the request filter
        // apiClientId
        def apiClientId = contexts.oauth2.accessToken.info.client_id
        if (apiClientId == null || apiClientId == "") {
            // in case of client credentials grant
            apiClientId = contexts.oauth2.accessToken.info.sub
        }
        // current time to filter the idempotency key expiration time (idempotencyKeyExpiration stored in seconds = creation time + 24hours)
        Instant currentInstantTime = Instant.now()
        logger.debug(SCRIPT_NAME + "apiClientId: " + apiClientId + ", current Instant: " + currentInstantTime +", in seconds: " + currentInstantTime.getEpochSecond())

        // filter by idempotency key, idempotency key expiration time (only valid for 24hours since has been created) and Oauth2ClientId
        def filter = "_queryFilter="+ idempotencyArgFieldToFilter + "+eq+%22" +
                URLEncoder.encode(idempotencyKeyHeaderValue, "UTF-8") + "%22" +
                "+and+" + idempotencyArgExpirationFieldToFilter + "+ge+" + currentInstantTime.getEpochSecond() +
                "+and+Oauth2ClientId+eq+%22" + apiClientId + "%22"

        logger.debug(SCRIPT_NAME + "Filter: " + filter)
        String fields = "_fields=_id,OBIntentObject"
        def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentArgObject + "?" + filter + "&" + fields
        logger.debug(SCRIPT_NAME + "Request URI: " + requestUri)

        // build the request
        Request intentRequest = new Request();
        intentRequest.setUri(requestUri);
        intentRequest.setMethod('GET');
        return http.send(intentRequest).thenAsync(intentResponse -> {
            intentRequest.close()
            logger.debug(SCRIPT_NAME + "Back from IDM")
            def intentResponseStatus = intentResponse.getStatus()
            if (intentResponseStatus != Status.OK) {
                message = "Failed to validate idempotent request"
                logger.error(SCRIPT_NAME + message)
                response.status = intentResponseStatus
                response.entity = "{ \"error\":\"" + message + "\"}"
                return newResultPromise(response)
            }

            def intentResponseResult = intentResponse.entity.getJson().result
            if (!intentResponseResult.isEmpty()) {
                logger.info("Found a intent for Oauth2ClientId: " + apiClientId + " with not expired " + idempotencyArgFieldToFilter +": " + idempotencyKeyHeaderValue)
                // For file submission the response needs to be Ok with empty entity
                if(idempotencyArgFieldToFilter == "FileIdempotencyKey") {
                    intentResponse.status = Status.OK
                    intentResponse.entity = ""
                    return newResultPromise(intentResponse)
                }
                intentResponse.status = Status.CREATED
                intentResponse.entity = JsonOutput.toJson(intentResponseResult[0].get("OBIntentObject"))
                return newResultPromise(intentResponse)
            }
            return next.handle(context, request)
        })
}
next.handle(context, request)
