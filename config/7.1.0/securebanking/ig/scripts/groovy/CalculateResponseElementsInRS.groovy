// Start script processing area
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[CalculateResponseElementsInRS] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")
def method = request.method

switch(method.toUpperCase()) {

    case "POST":
        def splitUri = request.uri.path.split("/")
        def version = splitUri[3]
        def currentApi = splitUri[5]

        // Create the RS Calculate elements API
        def requestURI = routeArgRsBaseURI + "/backoffice/" + version + "/" + currentApi + "/calculate-elements" + "?" +
                routeArgIntentQueryParameter + "=" + routeArgIntentType
        logger.debug(SCRIPT_NAME + " The updated raw request uri: " + requestURI)

        Request RSRequest = new Request()
        RSRequest.setUri(requestURI)
        RSRequest.setMethod('POST')
        RSRequest.setEntity(request.entity.getJson())

        logger.debug(SCRIPT_NAME + "Entity to be send to RS Calculate endpoint " + request.entity.getJson())

        return http.send(RSRequest).thenAsync(RSResponse -> {
            def RSResponseStatus = RSResponse.getStatus();
            if (RSResponseStatus != Status.OK) {
                message = "Failed to calculate elements"
                logger.error(SCRIPT_NAME + message)
                logger.error(SCRIPT_NAME + RSResponse.getEntity().getJson())
                def response = new Response(RSResponseStatus)
                response.status = RSResponseStatus
                response.entity = RSResponse.entity.getJson()
                return newResultPromise(response)
            }

            def RSResponseContent = RSResponse.getEntity();
            def RSResponseObject = RSResponseContent.getJson();

            logger.debug(SCRIPT_NAME + "The new entity: " + RSResponseObject.toString())
            request.setEntity(RSResponseContent.getJson());

            return next.handle(context, request)
        })
    default:
        logger.debug(SCRIPT_NAME + "Skipped")
}

next.handle(context, request)
