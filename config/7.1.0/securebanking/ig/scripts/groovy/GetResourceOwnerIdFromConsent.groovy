import groovy.json.JsonSlurper


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[GetResourceOwnerIdFromConsent] (" + fapiInteractionId + ") - ";
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
    PAYMENT_FILE_CONSENT("PFC_", "filePaymentsIntent"),
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
private Response getErrorResponse(String errorCode, String message) {
    logger.error("{} Message: {}. ErrorCode: {}", SCRIPT_NAME, message, errorCode)
    response = new Response(Status.BAD_REQUEST)
    response.setEntity(json(object(field("Code", Status.BAD_REQUEST.toString()),
            field("Errors", array(object(field("ErrorCode", errorCode),
                    field("Message", message)))))))
    return response
}
/**
 * Get intentId from Access token
 * @return intentId
 */
private String getIntentIdFromAccessToken() {
    try {
        return new JsonSlurper().parseText(contexts.oauth2.accessToken.info.claims).id_token.openbanking_intent_id.value
    } catch (Exception exception) {
        logger.debug("{} Couldn't get the intent id from the access token. {}", SCRIPT_NAME, exception.getMessage())
    }
    return null
}
/**
 * Get intentId from uri path elements
 * @return consentId
 */
private String getIntentIdFromUri(List<String> uriPathElements, int consentIdElementIndex) {
    logger.debug("{} searching consentId by index [{}] in the uri path elements [{}]", SCRIPT_NAME, consentIdElementIndex, uriPathElements)
    if (uriPathElements.size() < 2) {
        logger.error(SCRIPT_NAME + "Can't parse consent id from Uri path")
        return null
    }
    return uriPathElements[consentIdElementIndex]
}
/**
 * Compare values to check if those consent Ids match<br/>
 * Used to validate the consentIds from access token against the consentId from uri path
 * @param compareFrom
 * @param compareTo
 * @return true if values match, otherwise false
 */
private boolean doTheConsentIdsMatch(String compareFrom, String compareTo) {
    logger.debug("{} validating consent IDs matched", SCRIPT_NAME)
    if (compareFrom != compareTo) {
        return false
    }
    return true
}

/**
 * End definitions
 */


/**
 * start script
 */
List<String> uriPathElements = request.uri.getPathElements()

// Will be null when the access_token doesn't contains the intentId
String intentIdFromAccessToken = getIntentIdFromAccessToken()

// Funds confirmation request condition
boolean isFundsConfirmation = uriPathElements.contains("funds-confirmation")

// consentId default value retrieved from the access token or uri Path (../../{{consent ID}} or ../../{{consent ID}}/payment-details)
String intentId = intentIdFromAccessToken != null ? intentIdFromAccessToken :
        (
                uriPathElements.contains("payment-details") ? getIntentIdFromUri(uriPathElements, uriPathElements.size() - 2) :
                getIntentIdFromUri(uriPathElements, uriPathElements.size() - 1)
        )

// check if is funds-confirmation to validate the request and set the intentId from Uri path
logger.debug("{} funds confirmation request: {}", SCRIPT_NAME, isFundsConfirmation)
if (isFundsConfirmation) {
    // funds confirmation request '../{{consent ID}}/funds-confirmation'
    def intentIdFromUri = getIntentIdFromUri(uriPathElements, uriPathElements.size() - 2)
    if (!doTheConsentIdsMatch(intentIdFromAccessToken, intentIdFromUri)) {
        return getErrorResponse(
                "UK.OBIE.Resource.ConsentMismatch",
                String.format(
                        "The access token has been issued for the intent ID %s, and does not match with the intent ID %s retrieved from the request path",
                        intentIdFromAccessToken,
                        intentIdFromUri
                )
        )
    }
    intentId = intentIdFromAccessToken != null ? intentIdFromAccessToken : intentIdFromUri
}

// validates the intentId has been set
if (intentId == null) {
    return getErrorResponse(
            "UK.OBIE.Resource.InvalidFormat",
            "Can't parse consent id from inbound request"
    )
}

logger.debug(SCRIPT_NAME + "The intent id is: " + intentId)

def intentObject = ""

// logic to determine the intent type
def intentType = IntentType.identify(intentId)

if (intentType) {
    intentObject = intentType.getConsentObject();
} else {
    return getErrorResponse(
            "UK.OBIE.Parameter.Invalid",
            String.format("Can't parse consent type from inbound request, unknown consent type [%s].", intentType)
    )
}

// build the request to call IDM to retrieve the consent
def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentObject + "/" + intentId + "?_fields=_id,OBIntentObject,user/_id,accounts,account,apiClient/oauth2ClientId,apiClient/name,AccountId";
// IDM request call
if (request.getMethod() == "GET" || request.getMethod() == "POST") {
    Request intentRequest = new Request();
    intentRequest.setUri(requestUri);
    intentRequest.setMethod('GET');
    logger.debug("{} Back from IDM", SCRIPT_NAME)
    return http.send(intentRequest).thenAsync(intentResponse -> {
        intentRequest.close()
        logger.debug("{} Back from IDM", SCRIPT_NAME)
        def intentResponseStatus = intentResponse.getStatus();

        if (intentResponseStatus != Status.OK) {
            message = "Failed to get consent details"
            logger.error("{} {}", SCRIPT_NAME, message)
            response.status = intentResponseStatus
            response.entity = "{ \"error\":\"" + message + "\"}"
            return newResultPromise(response)
        }

        def intentResponseContent = intentResponse.getEntity();
        def intentResponseObject = intentResponseContent.getJson();

        if (intentResponseObject.apiClient == null) {
            message = "Orphan consent, The consent requested to get with id [" + intentResponseObject._id + "] doesn't have a apiClient related."
            logger.error("{} {}", SCRIPT_NAME, message)
            response.status = Status.BAD_REQUEST
            response.entity = "{ \"error\":\"" + message + "\"}"
            return newResultPromise(response)
        }

        attributes.put("resourceOwnerUsername", intentResponseObject.user ? intentResponseObject.user._id : null)
        logger.debug("{} Resource owner username: {}", SCRIPT_NAME, intentResponseObject.user._id)

        try {
            logger.debug("{} Debtor account identification: {}", SCRIPT_NAME, intentResponseObject.OBIntentObject.Data.Initiation)
            attributes.put("accountId", intentResponseObject.AccountId)
            // specific checks for funds confirmation requests
            if (isFundsConfirmation) {
                logger.debug("{} The consent status is {}", SCRIPT_NAME, intentResponseObject.OBIntentObject.Data.Status)
                if (intentResponseObject.OBIntentObject.Data.Status == "Authorised") {
                    def paymentAmount
                    if (intentType == IntentType.DOMESTIC_VRP_PAYMENT_CONSENT) {
                        // For VRP, checking the max individual amount to confirm that the debtor accounts has funds for the payment
                        paymentAmount = intentResponseObject.OBIntentObject.Data.ControlParameters.MaximumIndividualAmount.Amount
                    } else {
                        paymentAmount = intentResponseObject.OBIntentObject.Data.Initiation.InstructedAmount.Amount
                    }
                    logger.debug("{} Payment Amount: {}", SCRIPT_NAME, paymentAmount)
                    attributes.put("amount", paymentAmount)

                    attributes.put("version", uriPathElements[2])
                    logger.debug("{} version: {}", SCRIPT_NAME, uriPathElements[2])
                } else {
                    return newResultPromise(
                            getErrorResponse(
                                    "UK.OBIE.Resource.InvalidConsentStatus",
                                    String.format("Invalid Consent Status: %s", intentResponseObject.OBIntentObject.Data.Status)
                            )
                    )
                }
            }

            return next.handle(context, request)
        }
        catch (java.lang.Exception exception) {
            logger.error("{} {}", SCRIPT_NAME + message, exception)
            return newResultPromise(
                    getErrorResponse(
                            "UK.OBIE.Parameter.Invalid",
                            "Missing required parameters or headers"
                    )
            )
        }
    })
} else {
    return getErrorResponse(
            "UK.OBIE.Unsupported.UnexpectedError",
            String.format("Method %s not supported", request.getMethod())
    )
}
