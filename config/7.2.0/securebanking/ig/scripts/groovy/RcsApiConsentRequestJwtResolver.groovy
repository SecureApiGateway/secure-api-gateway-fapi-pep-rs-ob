/**
 * Script which resolves the location of the Consent Request JWT for calls to the RCS Backend (API)
 *
 * There are currently 2 backend API calls:
 * - /details which populates the UI, in this call the POST body contains the jwt as a raw string
 * - /decision which submits the consent decision, in this call the POST body contains a json object with the jwt in the "consentJwt" field
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[RcsApiConsentRequestJwtResolver] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def requestPath = contexts.router.remainingUri
if (requestPath.endsWith("/")) {
    requestPath = requestPath.substring(0, requestPath.length() - 1)
}
def consentJwt
if (requestPath.endsWith("/details")) {
    consentJwt = request.entity.getString()
} else if (requestPath.endsWith("/decision")) {
    consentJwt = request.entity.getJson().consentJwt
} else {
    logger.error(SCRIPT_NAME + " unsupported RCS backend uri: " + requestPath)
    return new Response(Status.BAD_REQUEST)
}

// Add the jwt to the attributes context so that it can be used by other filters
attributes.consentRequestJwt = consentJwt

next.handle(context, request)