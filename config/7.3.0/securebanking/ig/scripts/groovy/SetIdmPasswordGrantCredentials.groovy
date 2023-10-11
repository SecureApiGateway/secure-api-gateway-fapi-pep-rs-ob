/**
 * Script to replace client_credentials request string with password grant type and adding the credentials.
 *
 * This script is required when requesting an access_token to access IDM.
 */
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[SetIdmPasswordGrantCredentials] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def newEntity = request.getEntity().getString().replace('grant_type=client_credentials','grant_type=password&username=' + userId + '&password=' + java.net.URLEncoder.encode(password, 'UTF-8'))
logger.debug(SCRIPT_NAME + "Setting entity to [{}]", newEntity)
request.setEntity(newEntity)

return http.send(context, request)