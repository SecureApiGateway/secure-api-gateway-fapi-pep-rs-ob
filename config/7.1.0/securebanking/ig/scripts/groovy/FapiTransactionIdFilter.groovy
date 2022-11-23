import org.forgerock.services.context.TransactionIdContext
import org.forgerock.services.TransactionId

/**
 *  This script sets the TransactionIdContext to be the same value as the x-fapi-interaction-id 
 *  if it is set. This means that the X-ForgeRock-TransactionID header sent to the ForgeRock
 *  platform will be set to the same value as the x-fapi-interaction-id header. This will allow
 *  searching for all related log entries when a TPP provides a customer with the 
 *  x-fapi-interaction-id value returned in a failing request's response headers.
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[FapiTransactionIdFilter] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

String interactionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (interactionId != null) {
    logger.debug(SCRIPT_NAME + "Found x-fapi-interaction-id: " + interactionId + " setting as TransactionId")
    TransactionIdContext newContext = new TransactionIdContext(context, new TransactionId(interactionId));
    return next.handle(newContext, request);
}
return next.handle(context, request);