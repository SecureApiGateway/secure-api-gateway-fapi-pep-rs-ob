import groovy.json.JsonSlurper

SCRIPT_NAME = "[GetResourceOwnerIdFromConsent] - "
logger.debug(SCRIPT_NAME + "Running...")
/**
 *  definitions
 */
enum IntentType {
    ACCOUNT_ACCESS_CONSENT("AAC_", "accountAccessIntent"),
    PAYMENT_DOMESTIC_CONSENT("PDC_", "domesticPaymentIntent"),
    PAYMENT_DOMESTIC_SCHEDULED_CONSENT("PDSC_", "domesticScheduledPaymentIntent"),
    PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT("PDSOC_", "domesticStandingOrdersIntent"),
    PAYMENT_INTERNATIONAL_CONSENT("PIC_", "internationalPaymentIntent"),
    PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT("PISC_", "internationalScheduledPaymentIntent"),
    PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT("PISOC_", "internationalStandingOrdersIntent"),
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

    String getConsentObject() {
        return consentObject
    }
}

/**
 * Builds the error response
 * @return error response
 */
def getErrorResponse() {
    message = "Invalid Consent Status"
    errorCode = "UK.OBIE.Resource.InvalidConsentStatus"
    logger.error(SCRIPT_NAME + "Message: " + message + ". ErrorCode:" + errorCode)

    response = new Response(Status.BAD_REQUEST)

    Map<String,String> newBody = [
            Code: Status.BAD_REQUEST.toString()
    ]

    requestIds = request.headers.get("x-request-id")
    if (requestIds) {
        newBody.put("Id", requestIds.firstValue)
    }
    newBody.put("Message",  Status.BAD_REQUEST.toString())

    Map<String,String> errorList =[
            ErrorCode: errorCode,
            Message: message
    ]

    newBody.put("Errors", errorList)
    response.setEntity(newBody)
    return response;
}
/**
 * End definitions
 */


/**
 * start script
 */
def intentId
def splitUri
try {
    def slurper = new JsonSlurper()
    intentId = slurper.parseText(contexts.oauth2.accessToken.info.claims).id_token.openbanking_intent_id.value

} catch (Exception e) {
    logger.debug(SCRIPT_NAME + "Couldn't get the intent id from the access token.")
    splitUri = request.uri.path.split("/")

    // response object
    response = new Response(Status.OK)
    response.headers['Content-Type'] = "application/json"

    if (splitUri.length < 2) {
        message = SCRIPT_NAME + "Can't parse consent id from inbound request"
        logger.error(SCRIPT_NAME + message)
        response.status = Status.BAD_REQUEST
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    intentId = splitUri[5]
}

if (intentId == null) {
    message = SCRIPT_NAME + "Can't parse consent id from inbound request"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

logger.debug(SCRIPT_NAME + "The intent id is: " + intentId)

def intentObject = ""

def intentType = IntentType.identify(intentId)

if (intentType) {
    intentObject = intentType.getConsentObject();
} else {
    message = "Can't parse consent type from inbound request, unknown consent type [" + intentType + "]."
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=_id,OBIntentObject,user/_id,accounts,account,apiClient/oauth2ClientId,apiClient/name,AccountId";

if (request.getMethod() == "GET" || request.getMethod() == "POST") {
    Request intentRequest = new Request();
    intentRequest.setUri(requestUri);
    intentRequest.setMethod('GET');
    logger.debug(SCRIPT_NAME + "Back from IDM")
    return http.send(intentRequest).thenAsync(intentResponse -> {
        intentRequest.close()
        logger.debug(SCRIPT_NAME + "Back from IDM")

        def intentResponseStatus = intentResponse.getStatus();

        if (intentResponseStatus != Status.OK) {
            message = "Failed to get consent details"
            logger.error(SCRIPT_NAME + message)
            response.status = intentResponseStatus
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        def intentResponseContent = intentResponse.getEntity();
        def intentResponseObject = intentResponseContent.getJson();

        if (intentResponseObject.apiClient == null) {
            message = "Orfan consent, The consent requested to get with id [" + intentResponseObject._id + "] doesn't have a apiClient related."
            logger.error(SCRIPT_NAME + message)
            response.status = Status.BAD_REQUEST
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        attributes.put("resourceOwnerUsername", intentResponseObject.user ? intentResponseObject.user._id : null)
        logger.debug(SCRIPT_NAME + "Resource owner username: " + intentResponseObject.user._id)

        try {
            logger.debug(SCRIPT_NAME + "Debtor account identification: " + intentResponseObject.OBIntentObject.Data.Initiation)
            attributes.put("accountId", intentResponseObject.AccountId)

            splitUri = request.uri.path.split("/")
            if (splitUri.size() == 7 && splitUri[6] != null && splitUri[6] == "funds-confirmation") {
                if(intentResponseObject.OBIntentObject.Data.Status == "Consumed")
                {
                    logger.debug(SCRIPT_NAME + "The consent status is Consumed")
                    return newResultPromise(getErrorResponse())
                }

                attributes.put("amount", intentResponseObject.OBIntentObject.Data.Initiation.InstructedAmount.Amount)
                logger.debug(SCRIPT_NAME + "amount: " + intentResponseObject.OBIntentObject.Data.Initiation.InstructedAmount.Amount)

                attributes.put("version", splitUri[2])
                logger.debug(SCRIPT_NAME + "version: " + splitUri[2])
            }

        } catch (java.lang.Exception e) {
            message = "Missing required parameters or headers: "
            logger.error(SCRIPT_NAME + message + e)
            response = new Response(Status.BAD_REQUEST)
            response.entity = "{ \"error\":\"" + message + "\"}"
        }
        return next.handle(context, request)
    })
} else {
    message = "Method " + request.getMethod() + " not supported";
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

next.handle(context, request)
