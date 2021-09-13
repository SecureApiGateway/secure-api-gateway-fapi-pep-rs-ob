import groovy.json.JsonOutput


def splitUri =  request.uri.path.split("/")

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

if (splitUri.length < 2) {
    message = "Can't parse consent id from inbound request"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def consentType = splitUri[splitUri.length - 2]
def intentObject = ""

if (consentType == routeArgConsentPathAccountAccess) {
    intentObject = routeArgObjAccountAccessIntent
}
else if (consentType == routeArgConsentPathDomesticPayment) {
    intentObject = routeArgObjDomesticPaymentIntent
}
else {
    message = "Can't parse consent type from inbound request"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def intentId = splitUri[splitUri.length - 1]


Request intentRequest = new Request();
intentRequest.setMethod('GET');

intentRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=_id,Data,user/userName,accounts,account,apiClient/oauth2ClientId,apiClient/name")


http.send(intentRequest).then(intentResponse -> {
    intentRequest.close()
    logger.debug("Back from IDM")

    def intentResponseStatus = intentResponse.getStatus();

    if (intentResponseStatus != Status.OK) {
        message = "Failed to get consent details"
        logger.error(message)
        response.status = intentResponseStatus
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    def intentResponseContent = intentResponse.getEntity();
    def intentResponseObject = intentResponseContent.getJson();

    def responseObj = []

    if (consentType == routeArgConsentPathAccountAccess) {
        responseObj = [
                "id": intentResponseObject._id,
                "data": intentResponseObject.Data,
                "accountIds": intentResponseObject.accounts,
                "resourceOwnerUsername": intentResponseObject.user.userName,
                "oauth2ClientId": intentResponseObject.apiClient.oauth2ClientId,
                "oauth2ClientName": intentResponseObject.apiClient.name
        ]
    }
    else if (consentType == routeArgConsentPathDomesticPayment) {
        responseObj = [
                "id": intentResponseObject._id,
                "data": intentResponseObject.Data,
                "accountId": intentResponseObject.account,
                "resourceOwnerUsername": intentResponseObject.user.userName,
                "oauth2ClientId": intentResponseObject.apiClient.oauth2ClientId,
                "oauth2ClientName": intentResponseObject.apiClient.name
        ]
    }

    def responseJson = JsonOutput.toJson(responseObj);
    logger.debug("Final JSON " + responseJson)

    response.entity = responseJson
    return response

}).then(response -> { return response })
