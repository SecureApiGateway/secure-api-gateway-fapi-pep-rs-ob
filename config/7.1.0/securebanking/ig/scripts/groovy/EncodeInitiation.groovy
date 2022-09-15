import groovy.json.JsonOutput
import java.util.Base64

SCRIPT_NAME = "[EncodeInitiation] - "
logger.debug(SCRIPT_NAME + "Running...")

def initiationRequest = Base64.getEncoder().encodeToString(JsonOutput.toJson(request.entity.getJson().Data.Initiation).bytes)
logger.debug('request ' + initiationRequest)
attributes.put('initiationRequest', initiationRequest)

next.handle(context, request)