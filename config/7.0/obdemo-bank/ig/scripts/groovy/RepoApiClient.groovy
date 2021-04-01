import groovy.json.JsonOutput


// Fetch the API Client from IDM

Request apiClientRequest = new Request();
apiClientRequest.setMethod('GET');


def splitUri =  request.uri.path.split("/")

if (splitUri.length == 0) {
    logger.error("Can't parse api client ID from inbound request")
    return new Response(Status.BAD_REQUEST)
}

def apiClientId = splitUri[splitUri.length - 1];

logger.debug("Looking up API Client {}",apiClientId)

apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)

http.send(apiClientRequest).then(apiClientResponse -> {
    apiClientRequest.close()
    logger.debug("Back from IDM")

    def apiClientResponseStatus = apiClientResponse.getStatus();

    if (apiClientResponseStatus != Status.OK) {
        logger.error("Failed to get API Client details");
        return new Response(apiClientResponseStatus);
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
    logger.debug("Final JSON " + responseJson)

    def response = new Response(Status.OK)
    response.getHeaders().add("Content-Type","application/json");
    response.setEntity(responseJson);
    return response

}).then(response -> { return response })
