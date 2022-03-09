import groovy.json.JsonOutput

import java.text.SimpleDateFormat

/**
 *  definitions
 */
def buildPatchRequest(incomingRequest) {
    def body = [];

    if (incomingRequest.data && incomingRequest.data.Status) {
        body.push([
                "operation": "replace",
                "field"    : "/Data/Status",
                "value"    : incomingRequest.data.Status
        ]);

        def tz = TimeZone.getTimeZone("UTC");
        def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(tz);
        def nowAsISO = df.format(new Date());

        body.push([
                "operation": "replace",
                "field"    : "/Data/StatusUpdateDateTime",
                "value"    : nowAsISO
        ]);
    }

    if (incomingRequest.resourceOwnerUsername) {
        body.push([
                "operation": "replace",
                "field"    : "/user",
                "value"    : ["_ref": "managed/" + routeArgObjUser + "/" + incomingRequest.resourceOwnerUsername]
        ]);
    }

    if (incomingRequest.accountIds) {
        body.push([

                "operation": "replace",
                "field"    : "/accounts",
                "value"    : incomingRequest.accountIds

        ]);
    }

    // Domestic Payment Intent only

    if (incomingRequest.data && incomingRequest.data.DebtorAccount) {
        body.push([

                "operation": "add",
                "field"    : "/Data/DebtorAccount",
                "value"    : incomingRequest.data.DebtorAccount
        ]);
    }

    return body
}

def convertIDMResponse(intentResponseObject, intentType) {
    def responseObj = [];
    switch (intentType){
        case IntentType.ACCOUNT_ACCESS_CONSENT:
            responseObj = [
                    "id"                   : intentResponseObject._id,
                    "data"                 : intentResponseObject.Data,
                    "accountIds"           : intentResponseObject.accounts,
                    "resourceOwnerUsername": intentResponseObject.user ? intentResponseObject.user._id : null,
                    "oauth2ClientId"       : intentResponseObject.apiClient.oauth2ClientId,
                    "oauth2ClientName"     : intentResponseObject.apiClient.name
            ]
            break
        case IntentType.PAYMENT_DOMESTIC_CONSENT:
            responseObj = [
                    "id"                   : intentResponseObject._id,
                    "data"                 : intentResponseObject.Data,
                    "resourceOwnerUsername": intentResponseObject.user ? intentResponseObject.user._id : null,
                    "oauth2ClientId"       : intentResponseObject.apiClient.oauth2ClientId,
                    "oauth2ClientName"     : intentResponseObject.apiClient.name
            ]
            break
    }

    return responseObj;

}

enum IntentType {
    ACCOUNT_ACCESS_CONSENT("AAC_", "accountAccessIntent"),
    PAYMENT_DOMESTIC_CONSENT("PDC_","domesticPaymentIntent"),
    PAYMENT_DOMESTIC_SCHEDULED_CONSENT("PDSC_", "domesticScheculedPaymentIntent"),
    PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT("PDSOC_", "domesticStandingOrdersPaymentIntent"),
    PAYMENT_INTERNATIONAL_CONSENT("PIC_", "internationalPaymentIntent"),
    PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT("PISC_", "internationalScheduledPaymentIntent"),
    PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT("PISOC_", "internationalStandingOrdersPaymentIntent"),
    PAYMENT_FILE_CONSENT("PFC_", "filePaymentIntent"),
    FUNDS_CONFIRMATION_CONSENT("FCC_", "fundsConfirmationIntent"),
    DOMESTIC_VRP_PAYMENT_CONSENT("DVRP_", "domesticVrpPaymentIntent")

    private String intentIdPrefix;
    private String consentObject;

    IntentType(String intentIdPrefix, String consentObject) {
        this.intentIdPrefix = intentIdPrefix
        this.consentObject = consentObject
    }

    static IntentType identify(String intentId) {
        IntentType[] types = values()
        Optional<IntentType> optional = Arrays.stream(types).filter(type -> intentId.startsWith(type.intentIdPrefix)).findFirst()
        if (optional.isPresent()) {
            return optional.get()
        }
        return null;
    }

    String getIntentIdPrefix() {
        return intentIdPrefix
    }
    String getConsentObject(){
        return consentObject
    }
}
/**
 * End definitions
 */


/**
 * start script
 */
def splitUri = request.uri.path.split("/")

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

def intentId = splitUri[splitUri.length - 1]
def intentObject = ""

def intentType = IntentType.identify(intentId)

if(intentType){
    intentObject = intentType.getConsentObject();
} else {
    message = "Can't parse consent type from inbound request, unknown consent type [" + intentType + "]."
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=_id,Data,user/_id,accounts,account,apiClient/oauth2ClientId,apiClient/name";

if (request.getMethod() == "GET") {
    Request intentRequest = new Request();
    intentRequest.setUri(requestUri);
    intentRequest.setMethod('GET');
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

        def responseObj = convertIDMResponse(intentResponseObject, intentType);

        def responseJson = JsonOutput.toJson(responseObj);
        logger.debug("Final JSON " + responseJson)

        response.entity = responseJson
        return response

    }).then(response -> { return response })
} else if (request.getMethod() == "PATCH") {
    Request patchRequest = new Request();
    patchRequest.setMethod('POST');
    patchRequest.setUri(requestUri + "&_action=patch");
    patchRequest.getHeaders().add("Content-Type", "application/json");
    patchRequest.setEntity(JsonOutput.toJson(buildPatchRequest(request.getEntity().getJson())))

    http.send(patchRequest).then(patchResponse -> {
        patchRequest.close()
        logger.debug("Back from IDM")
        def patchResponseContent = patchResponse.getEntity();
        def patchResponseStatus = patchResponse.getStatus();

        logger.debug("status " + patchResponseStatus);
        logger.debug("entity " + patchResponseContent);

        if (patchResponseStatus != Status.OK) {
            message = "Failed to patch consent"
            logger.error(message)
            response.status = patchResponseStatus
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        def patchResponseObject = patchResponseContent.getJson();
        def responseObj = convertIDMResponse(patchResponseObject, intentType);
        Response response = new Response(Status.OK)
        response.setEntity(JsonOutput.toJson(responseObj));
        response.headers['Content-Type'] = "application/json";
        return response
    }).then(response -> { return response })

} else {
    message = "Method " + request.getMethod() + " not supported";
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}
