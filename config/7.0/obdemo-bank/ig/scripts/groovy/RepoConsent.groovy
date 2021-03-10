import groovy.json.JsonOutput


def splitUri =  request.uri.path.split("/")

if (splitUri.length < 2) {
    logger.error("Can't parse consent id from inbound request")
    return new Response(Status.BAD_REQUEST)
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
    logger.error("Can't parse consent type from inbound request")
    return new Response(Status.BAD_REQUEST)
}

def intentId = splitUri[splitUri.length - 1]


Request intentRequest = new Request();
intentRequest.setMethod('GET');

intentRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=Data,user/userName,accounts,apiClient/oauth2ClientId")


http.send(intentRequest).then(intentResponse -> {
    intentRequest.close()
    logger.debug("Back from IDM")

    def intentResponseStatus = intentResponse.getStatus();

    if (intentResponseStatus != Status.OK) {
        logger.error("Failed to get consent details");
        return new Response(intentResponseStatus);
    }

    def intentResponseContent = intentResponse.getEntity();
    def intentResponseObject = intentResponseContent.getJson();

    def responseObj = [
            "data": intentResponseObject.Data,
            "accounts": intentResponseObject.accounts,
            "user": intentResponseObject.user.userName,
            "oauth2ClientId": intentResponseObject.apiClient.oauth2ClientId
    ]
    def responseJson = JsonOutput.toJson(responseObj);
    logger.debug("Final JSON " + responseJson)
    def response = new Response(Status.OK)
    response.getHeaders().add("Content-Type","application/json");
    response.setEntity(responseJson);
    return response

}).then(response -> { return response })
