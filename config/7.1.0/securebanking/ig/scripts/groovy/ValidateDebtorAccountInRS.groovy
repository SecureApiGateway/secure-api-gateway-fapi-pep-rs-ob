import java.net.URLEncoder
// Start script processing area
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ValidateDebtorAccountInRS] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")
def method = request.method


switch(method.toUpperCase()) {

    case "POST":
        def debtorAccount = request.entity.getJson().Data.Initiation.DebtorAccount
        if(debtorAccount !=null){
            def requestURI = routeArgRsBaseURI + "/backoffice/accounts/search/findByAccountIdentifiers" +
                    "?name=" + URLEncoder.encode(debtorAccount.Name.toString(), "UTF-8") + "&identification=" + debtorAccount.Identification +
                    "&schemeName=" + debtorAccount.SchemeName

            logger.debug(SCRIPT_NAME + " findByAccountIdentifiers raw request uri: " + requestURI)
            Request rsRequest = new Request()
            rsRequest.setUri(requestURI)
            rsRequest.setMethod('GET')

            return http.send(rsRequest).thenAsync(rsResponse -> {
                def rsResponseStatus = rsResponse.getStatus();
                if (rsResponseStatus != Status.OK) {
                    message = "Failed to find the debtor account by account identifiers"
                    logger.error(SCRIPT_NAME + message)
                    logger.error(SCRIPT_NAME + rsResponse.getEntity().getJson())
                    def response = new Response(rsResponseStatus)
                    response.status = rsResponseStatus
                    response.entity = rsResponse.entity.getJson()
                    return newResultPromise(response)
                }
                if (rsResponse.getEntity().isRawContentEmpty()) {
                    message = "Invalid debtor account, the debtor account provided in the consent does not exist"
                    logger.error(SCRIPT_NAME + message)
                    response = new Response(Status.BAD_REQUEST)
                    response.headers['Content-Type'] = "application/json"
                    response.status = Status.BAD_REQUEST
                    response.entity = "{ \"error\":\"" + message + "\"}"
                    return newResultPromise(response)
                }
                return next.handle(context, request)
            })
        }
    default:
        logger.debug(SCRIPT_NAME + "Skipped")
}

next.handle(context, request)
