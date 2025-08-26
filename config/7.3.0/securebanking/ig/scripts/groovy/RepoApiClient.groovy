import groovy.json.JsonOutput
import static org.forgerock.util.CloseSilentlyAsyncFunction.closeSilently;
import static org.forgerock.util.promise.NeverThrowsException.neverThrownAsync;

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[RepoApiClient] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

// Fetch the API Client from IDM
Request apiClientRequest = new Request();
apiClientRequest.setMethod('GET');

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def splitUri =  request.uri.path.split("/")

if (splitUri.length == 0) {
    message = "Can't parse api client ID from inbound request"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def apiClientId = splitUri[splitUri.length - 1];

logger.debug(SCRIPT_NAME + "Looking up API Client {}",apiClientId)

apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
idmService.send(context, apiClientRequest)
          .thenAsync(closeSilently(response -> {
              logger.debug(SCRIPT_NAME + "Back from IDM")
              def apiClientResponseStatus = apiClientResponse.getStatus();

              if (apiClientResponseStatus != Status.OK) {
                  message = "Failed to get API Client details"
                  logger.error(message)
                  response.status = apiClientResponseStatus
                  response.entity = "{ \"error\":\"" + message + "\"}"
                  return response
              }
              return response.getEntity()
                             .getJsonAsync()
                             .then(json -> {
                                 def responseObj = [
                                         "id"            : json.id,
                                         "name"          : json.name,
                                         "officialName"  : json.name,
                                         "oauth2ClientId": json.oauth2ClientId,
                                         "logoUri"       : json.logoUri
                                 ]

                                 def responseJson = JsonOutput.toJson(responseObj);
                                 logger.debug(SCRIPT_NAME + "Final JSON " + responseJson)

                                 response.entity = responseJson;
                                 return response
                             });
          }), neverThrownAsync())
