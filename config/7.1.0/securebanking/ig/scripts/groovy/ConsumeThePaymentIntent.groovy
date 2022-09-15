import groovy.json.JsonOutput

SCRIPT_NAME = "[ConsumeThePaymentIntent] - "
logger.debug(SCRIPT_NAME + "Running...")

/**
 *  definitions
 */
def buildPatchRequest() {
    def body = [];

    body.push([
            "operation": "replace",
            "field"    : "/Data/Status",
            "value"    : "Consumed"
    ]);

    return body
}

enum IntentType {
    ACCOUNT_ACCESS_CONSENT("AAC_", "accountAccessIntent"),
    PAYMENT_DOMESTIC_CONSENT("PDC_","domesticPaymentIntent"),
    PAYMENT_DOMESTIC_SCHEDULED_CONSENT("PDSC_", "domesticScheduledPaymentIntent"),
    PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT("PDSOC_", "domesticStandingOrderIntent"),
    PAYMENT_INTERNATIONAL_CONSENT("PIC_", "internationalPaymentIntent"),
    PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT("PISC_", "internationalScheduledPaymentIntent"),
    PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT("PISOC_", "internationalStandingOrderIntent"),
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
next.handle(context, request).thenOnResult({ response ->
    //Verify the response status
    if (response.status != Status.CREATED) {
        //This script should be executed only if the response status is 201 CREATED
        logger.debug(SCRIPT_NAME + "Skipping the filter because the response status is " + response.status)
    } else {
        // If the response status is 201 CREATED, the intent status should be changed to Consumed
        logger.debug(SCRIPT_NAME + "The response status is " + response.status + ". The intent status will be updated to Consumed.")

        //Get the intent Id from the request body
        def intentId = request.entity.getJson().Data.ConsentId
        logger.debug(SCRIPT_NAME + "The intent id is " + intentId)

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
        logger.debug(SCRIPT_NAME + "The request uri is " + requestUri)

        Request patchRequest = new Request();
        patchRequest.setMethod('POST');
        patchRequest.setUri(requestUri + "&_action=patch");
        patchRequest.getHeaders().add("Content-Type", "application/json");
        patchRequest.setEntity(JsonOutput.toJson(buildPatchRequest()))

        http.send(patchRequest).thenAsync(patchResponse -> {
            def responseStatus = patchResponse.getStatus();
            logger.debug(SCRIPT_NAME + "Get API client response status: " + responseStatus)
            logger.debug(SCRIPT_NAME + "The intent status was changed to Consumed")
        })
    }
})