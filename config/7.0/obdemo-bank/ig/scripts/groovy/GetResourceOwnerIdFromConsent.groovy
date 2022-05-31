SCRIPT_NAME = "[GetResourceOwnerIdFromConsent] - "
logger.debug(SCRIPT_NAME + " Running...")
/**
 *  definitions
 */
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
    message = SCRIPT_NAME + "Can't parse consent id from inbound request"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def intentId = splitUri[5]

def intentObject = ""

def intentType = IntentType.identify(intentId)

if(intentType){
    intentObject = intentType.getConsentObject();
} else {
    message = "Can't parse consent type from inbound request, unknown consent type [" + intentType + "]."
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=_id,Data,user/_id,accounts,account,apiClient/oauth2ClientId,apiClient/name";

if (request.getMethod() == "GET") {
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

        if(intentResponseObject.apiClient == null){
            message = "Orfan consent, The consent requested to get with id [" + intentResponseObject._id + "] doesn't have a apiClient related."
            logger.error(SCRIPT_NAME + message)
            response.status = Status.BAD_REQUEST
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        attributes.put("resourceOwnerUsername", intentResponseObject.user ? intentResponseObject.user._id : null)
        logger.debug(SCRIPT_NAME + "Resource owner username: " + intentResponseObject.user._id)

        if (splitUri.size() == 7 && splitUri[6] != null && splitUri[6] == "funds-confirmation")
        {
            try{
                logger.debug(SCRIPT_NAME + "Debtor account identification: " + intentResponseObject.Data.Initiation)
                attributes.put("accountId", intentResponseObject.Data.Initiation.DebtorAccount.AccountId)
                logger.debug(SCRIPT_NAME + "Debtor account identification: " + intentResponseObject.Data.Initiation.DebtorAccount.AccountId)

                attributes.put("amount", intentResponseObject.Data.Initiation.InstructedAmount.Amount)
                logger.debug(SCRIPT_NAME + "amount: " + intentResponseObject.Data.Initiation.InstructedAmount.Amount)

                attributes.put("version", splitUri[2])
                logger.debug(SCRIPT_NAME + "version: " + splitUri[2])

            } catch (java.lang.Exception e) {
                logger.debug(SCRIPT_NAME + "The debtor account identification wasn't retrieve: " + e)
            }
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
