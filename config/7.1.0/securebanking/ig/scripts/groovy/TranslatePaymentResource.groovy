def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[TranslatePaymentResource] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

request.headers.add(routeArgAccountIdHeader, attributes.get("accountId"))

next.handle(context, request)
