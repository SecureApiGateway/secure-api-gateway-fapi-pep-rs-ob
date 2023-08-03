import org.forgerock.services.context.TransactionIdContext
import org.forgerock.services.TransactionId
import org.slf4j.MDC

/**
 *  This script sets the TransactionIdContext to be the same value as the x-fapi-interaction-id 
 *  if it is set. This means that the X-ForgeRock-TransactionID header sent to the ForgeRock
 *  platform will be set to the same value as the x-fapi-interaction-id header. This will allow
 *  searching for all related log entries when a TPP provides a customer with the 
 *  x-fapi-interaction-id value returned in a failing request's response headers.
 */

FAPI_INTERACTION_ID = "x-fapi-interaction-id"
def fapiInteractionId = request.getHeaders().getFirst(FAPI_INTERACTION_ID)
if(fapiInteractionId == null) fapiInteractionId = "No " + FAPI_INTERACTION_ID
SCRIPT_NAME = "[FapiTransactionIdFilter] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

if (fapiInteractionId != null) {
    logger.debug(SCRIPT_NAME + "Found x-fapi-interaction-id: " + fapiInteractionId + " setting as TransactionId")
    TransactionIdContext newContext = new TransactionIdContext(context, new TransactionId(fapiInteractionId))

    // Add the x-fapi-interaction-id to the MDC context for logging purposes, ensure the previously set value is restored
    final String previousMdcFapiInteractionId = MDC.get(FAPI_INTERACTION_ID)
    MDC.put(FAPI_INTERACTION_ID, fapiInteractionId)
    try {
        return next.handle(newContext, request).thenAlways(() -> removeFapiInteractionIdFromMdc(previousMdcFapiInteractionId))
    } finally {
        removeFapiInteractionIdFromMdc(previousMdcFapiInteractionId)
    }
}
return next.handle(context, request)

// This idiom has been copied from org.forgerock.openig.filter.MdcRouteIdFilter
private void removeFapiInteractionIdFromMdc(String previousFapiInteractionId) {
    if (previousFapiInteractionId == null) {
        MDC.remove(FAPI_INTERACTION_ID)
    } else {
        MDC.put(FAPI_INTERACTION_ID, previousFapiInteractionId)
    }
}