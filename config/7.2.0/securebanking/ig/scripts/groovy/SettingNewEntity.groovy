
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[SettingNewEntity] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def newEntity = request.getEntity().getString().replace('grant_type=client_credentials','grant_type=password&username=' + userId + '&password=' + java.net.URLEncoder.encode(password, 'UTF-8'))
logger.debug(SCRIPT_NAME + "Setting entity to [{}]", newEntity)
request.setEntity(newEntity)

return http.send(context, request)