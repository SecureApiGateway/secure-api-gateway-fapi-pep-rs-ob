import groovy.json.JsonOutput

SCRIPT_NAME = "[RepoApiClient] - "
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

http.send(apiClientRequest).then(apiClientResponse -> {
    apiClientRequest.close()
    logger.debug(SCRIPT_NAME + "Back from IDM")

    def apiClientResponseStatus = apiClientResponse.getStatus();

    if (apiClientResponseStatus != Status.OK) {
        message = "Failed to get API Client details"
        logger.error(message)
        response.status = apiClientResponseStatus
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    def apiClientResponseContent = apiClientResponse.getEntity();
    def apiClientResponseObject = apiClientResponseContent.getJson();

    def responseObj = [
            "id": apiClientResponseObject.id,
            "name": apiClientResponseObject.name,
            "officialName": apiClientResponseObject.name,
            "oauth2ClientId": apiClientResponseObject.oauth2ClientId,
            "logoUri": apiClientResponseObject.logoUri
    ]

    def responseJson = JsonOutput.toJson(responseObj);
    logger.debug(SCRIPT_NAME + "Final JSON " + responseJson)

    response.entity = responseJson;
    return response

}).then(response -> { return response })
