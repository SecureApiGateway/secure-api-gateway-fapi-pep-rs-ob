import groovy.json.JsonOutput
import java.util.Base64

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[EncodeInitiation] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def initiationRequest = Base64.getEncoder().encodeToString(JsonOutput.toJson(request.entity.getJson().Data.Initiation).bytes)
logger.debug('request ' + initiationRequest)
attributes.put('initiationRequest', initiationRequest)

next.handle(context, request)