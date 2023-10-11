
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ReturnInvalidCnfKeyError] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def response = new Response(Status.UNAUTHORIZED);
message = "invalid_client"
logger.error(SCRIPT_NAME + message)
response.setEntity("{ \"error\":\"" + message + "\"}")
response.headers['WWW-Authenticate'] = "Bearer"

return response