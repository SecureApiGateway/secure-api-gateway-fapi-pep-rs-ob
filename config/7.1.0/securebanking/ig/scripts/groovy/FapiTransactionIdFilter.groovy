import org.forgerock.services.context.TransactionIdContext
import org.forgerock.services.TransactionId

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