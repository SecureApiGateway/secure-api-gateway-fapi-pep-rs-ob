import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.HttpHeaderNames
import groovy.json.JsonSlurper

/**
 * This script is comparing the consentId from the request payload versus the consentId from the provided access token.
 * By doing this comparison, we prevent resources being submitted with a token obtained for another consent.
 */

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID);
if (fapiInteractionId == null) { fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'}
SCRIPT_NAME = '[ConsentIdValidator] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

// Get the intent id from the access token
def accessTokenIntentId = attributes.openbanking_intent_id

if (!accessTokenIntentId) {
    throw new IllegalStateException("openbanking_intent_id claim is missing from the attributes context");
}

// Get the intent Id from the request body
def requestIntentId = request.entity.getJson().Data.ConsentId

logger.debug(SCRIPT_NAME + 'Comparing token intent id {} with request intent id {}', accessTokenIntentId, requestIntentId)

// Compare the id's and only allow the filter chain to proceed if they exists and they match
if (requestIntentId && accessTokenIntentId == requestIntentId) {
    // Request is valid, allow it to pass
    return next.handle(context, request)
} else {
    Response response = new Response(Status.UNAUTHORIZED)
    String message = 'consentId from the request does not match the openbanking_intent_id claim from the access token'
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = 'application/json'
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}