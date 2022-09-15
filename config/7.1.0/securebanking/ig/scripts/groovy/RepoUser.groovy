import groovy.json.JsonOutput

SCRIPT_NAME = "[RepoUser] - "
logger.debug(SCRIPT_NAME + "Running...")

// Fetch the API Client from IDM
Request userRequest = new Request();
userRequest.setMethod('GET');

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

def userId = splitUri[splitUri.length - 1];

logger.debug(SCRIPT_NAME + "Looking up API User {}",userId)

userRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjUser + "/" + userId)

http.send(userRequest).then(userResponse -> {
    userRequest.close()
    logger.debug(SCRIPT_NAME + "Back from IDM")

    def userResponseStatus = userResponse.getStatus();

    if (userResponseStatus != Status.OK) {
        message = "Failed to get user details"
        logger.error(SCRIPT_NAME + message)
        response.status = userResponseStatus
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    def userResponseContent = userResponse.getEntity();
    def userResponseObject = userResponseContent.getJson();
    logger.debug(SCRIPT_NAME + "response JSON " + userResponseObject);

    def responseObj = [
            "id": userResponseObject._id,
            "userName": userResponseObject.userName,
            "givenName": userResponseObject.givenName,
            "surname": userResponseObject.sn,
            "mail": userResponseObject.mail,
            "accountStatus": userResponseObject.accountStatus
    ]

    def responseJson = JsonOutput.toJson(responseObj);
    logger.debug(SCRIPT_NAME + "Final JSON " + responseJson)

    response.entity = responseJson;
    return response

}).then(response -> { return response })
