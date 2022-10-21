import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*

// Start script processing area

SCRIPT_NAME = "[ValidateFileConsent] - "
logger.debug(SCRIPT_NAME + "Running...")

def splitUri = request.uri.path.split("/")
def version = splitUri[3]
def consentId = splitUri[6]

Promise<Boolean, NeverThrowsException> validationResult = callRsToValidateFile(routeArgRsBaseURI, version, consentId);

return validationResult.thenAsync(validfFile -> {
    if (Boolean.FALSE.equals(validfFile)) {
        return newResultPromise(getFileValidationErrorResponse())
    }

    return next.handle(context, request)

})

// Start method definition area

/**
 * Calls RS to validate the request payload which should be either a JSON file, or an XML file
 *
 * @param routeArgRsBaseURI - the RS URL
 * @param version the API version called
 * @param consentId the consent ID
 * @return
 */
def callRsToValidateFile(String routeArgRsBaseURI, String version, String consentId) {
    def requestURI = routeArgRsBaseURI + "/backoffice/" + version + "/file-payment-consent/" +
            consentId + "/file/validate"
    logger.debug(SCRIPT_NAME + " The updated request uri: " + requestURI)

    Request RSRequest = new Request()
    RSRequest.setUri(requestURI)
    RSRequest.setMethod('POST')
    RSRequest.getHeaders().add("Authorization", request.getHeaders().getFirst("Authorization"));
    RSRequest.getHeaders().add("Content-Type", request.getHeaders().getFirst("Content-Type"));
    RSRequest.setEntity(request.entity.getString())

    if (request.headers.get("x-fapi-financial-id") != null) {
        RSRequest.putHeaders(request.headers.get("x-fapi-financial-id"))
    }

    logger.debug(SCRIPT_NAME + "Entity to be send to RS file payment endpoint " + request.entity.getString())

    return http.send(RSRequest).thenAsync(RSResponse -> {
        def RSResponseStatus = RSResponse.getStatus();

        logger.debug(SCRIPT_NAME + "Validation response: " + RSResponseStatus)

        if (RSResponseStatus != Status.OK) {
            message = "Failed to validate file consent"
            logger.error(SCRIPT_NAME + message)
            return newResultPromise(false)
        }
        return newResultPromise(true)
    })
}

/**
 * Builds the file validation failure error response
 * @return error response
 */
def getFileValidationErrorResponse() {
    message = "Invalid payment file"
    logger.error(SCRIPT_NAME + message)
    Response response = new Response(Status.BAD_REQUEST)
    response.setEntity("{ \"error\":\"" + message + "\"}")
    return response;
}