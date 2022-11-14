
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ReturnPolicyValidationError] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def response = new Response(Status.UNAUTHORIZED);
message = "policy_validation_failed"
logger.error(SCRIPT_NAME + message)
response.setEntity("{ \"error\":\"" + message + "\"}")

return response