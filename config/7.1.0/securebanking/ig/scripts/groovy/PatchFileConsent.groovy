import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import groovy.json.JsonOutput

// Start script processing area
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[PatchFileConsent] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def splitUri = request.uri.path.split("/")
def consentId = splitUri[6]

def requestUri = routeArgIdmBaseUri + "/openidm/managed/filePaymentsIntent/" + consentId + "?_fields=_id,FileContent,OBIntentObject/Data/Status";
logger.debug(SCRIPT_NAME + "The request uri is " + requestUri)

Request patchRequest = new Request();
patchRequest.setMethod('POST');
patchRequest.setUri(requestUri + "&_action=patch");
patchRequest.getHeaders().add("Content-Type", "application/json");
patchRequest.setEntity(JsonOutput.toJson(buildPatchRequest(request.entity.getString())))

http.send(patchRequest).thenAsync(patchResponse -> {
    def responseStatus = patchResponse.getStatus();
    logger.debug(SCRIPT_NAME + "Patch filePaymentsIntent status: " + responseStatus)
    logger.debug(SCRIPT_NAME + "Patch filePaymentsIntent response entity: " + patchResponse.entity.getJson())

    if (responseStatus != Status.OK) {
        return newResultPromise(getPatchError())
    }

    logger.debug(SCRIPT_NAME + "The intent status was changed to AwaitingAuthorisation and FileContent has been added to the intent object.")
    return newResultPromise(new Response(Status.OK))
})

// Start method declaration area

def buildPatchRequest(String fileContent) {
    def body = [];

    body.push([
            "operation": "replace",
            "field"    : "FileContent",
            "value"    : fileContent
    ]);

    body.push([
            "operation": "replace",
            "field"    : "OBIntentObject/Data/Status",
            "value"    : "AwaitingAuthorisation"
    ]);

    return body
}

/**
 * Builds an error message for IDM patch failure scenario
 * @return error response
 */
def getPatchError() {
    message = "Consent could not be patched"
    logger.error(SCRIPT_NAME + message)
    Response response = new Response(Status.BAD_REQUEST)
    response.setEntity("{ \"error\":\"" + message + "\"}")
    return response;
}