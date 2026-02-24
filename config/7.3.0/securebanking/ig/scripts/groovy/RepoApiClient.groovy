import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.http.protocol.Status.OK
import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import static org.forgerock.util.Closeables.closeSilently

import org.forgerock.util.promise.NeverThrowsException
import org.forgerock.json.JsonValue

/**
 * Scripted Handler implementation to fetch an API client from the repo.
 */

// FAPI logging
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[RepoApiClient] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

return handle(context, request)

/**
 * Fetch the API client from the repo.
 * @param unusedContext Context is unused
 * @param request Request to obtain API client
 * @return Promise of a Response containing the API client
 */
Promise<Response, NeverThrowsException> handle(final Context unusedContext, final Request request) {
    def apiClientId = extractApiClientId(request)
    if (apiClientId == null) {
        message = "Can't parse api client ID from inbound request"
        logger.error(SCRIPT_NAME + message)
        return newResponsePromise(fail(BAD_REQUEST, message))
    }

    // Fetch the API Client from the repo (IDM)
    Request apiClientRequest = new Request();
    def apiClientUri = routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId
    apiClientRequest.setMethod('GET');
    apiClientRequest.setUri(apiClientUri)

    logger.debug(SCRIPT_NAME + "Obtaining API client data from repo {}", apiClientUri)
    return http.send(apiClientRequest)
            .thenAlways(() -> closeSilently(apiClientRequest))
            .thenAsync(apiClientResponse -> handleApiClientResponse(apiClientResponse))
            .thenCatch(exception -> {
                logger.error(SCRIPT_NAME + "Exception obtaining API client data from repo {}", apiClientUri, exception)
                fail(apiClientResponse.getStatus(), exception.getMessage())
            })
            .thenCatchRuntimeException(exception -> {
                logger.error(SCRIPT_NAME + "Exception obtaining API client data from repo {}", apiClientUri, exception)
                fail(apiClientResponse.getStatus(), exception.getMessage())
            })
}

private String extractApiClientId(Request request) {
    // Extract the API client ID from the REST request
    def splitUri = request.uri.path.split("/")
    if (splitUri.length == 0) {
        return null
    }
    def apiClientId = splitUri[splitUri.length - 1]
    logger.debug(SCRIPT_NAME + "Looking up API Client {}", apiClientId)
    return apiClientId
}

private Promise<Response, NeverThrowsException> handleApiClientResponse(Response apiClientResponse) {
    logger.debug(SCRIPT_NAME + "Handling API client response")
    return processResponseContent(apiClientResponse)
            .thenAlways(() -> closeSilently(apiClientResponse))
            .then(apiClientResponseJson -> transformApiClientResponse(apiClientResponseJson))
}

private Promise<JsonValue, Exception> processResponseContent(final Response apiClientResponse) {
    if (!(OK.equals(apiClientResponse.getStatus()))) {
        logger.error("Unable to communicate with API client endpoint - status code {}",
                     apiClientResponse.getStatus().getCode())
        return newExceptionPromise(
                new IOException("Failed to get API Client details - problem communicating with repo"))
    }
    ContentTypeHeader contentTypeHeader = ContentTypeHeader.valueOf(apiClientResponse)
    String contentType = contentTypeHeader != null ? contentTypeHeader.getType() : null
    if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
        logger.error("API client endpoint response has unexpected content-type {}", contentType)
        return newExceptionPromise(
                new IOException("Failed to get API Client details - unexpected content " + contentType))
    }
    return getJsonContentAsync(apiClientResponse)
}

private static Promise<JsonValue, Exception> getJsonContentAsync(final Response response) {
    return response.getEntity()
                   .getJsonAsync()
                   .then(jsonContent -> new JsonValue(jsonContent).expect(Map.class))
                   .thenCatch(exception -> {
                       throw new IOException("Evaluation response has malformed response JSON");
                   })
}

private Response transformApiClientResponse(JsonValue apiClientResponseJson) {
    JsonValue transformedResponseJson = json(object(
            field("id", apiClientResponseJson.get("id")),
            field("name", apiClientResponseJson.get("name")),
            field("officialName", apiClientResponseJson.get("name")),
            field("oauth2ClientId", apiClientResponseJson.get("oauth2ClientId")),
            field("logoUri", apiClientResponseJson.get("logoUri"))))
    logger.debug(SCRIPT_NAME + "Transformed JSON {}", transformedResponseJson)
    Response transformedResponse = new Response(Status.OK)
    transformedResponse.getEntity().setJson(transformedResponseJson);
    return transformedResponse
}

private Response fail(Status errorStatus, String errorMessage) {
    Response response = new Response(OK)
    response.headers['Content-Type'] = "application/json"
    response.status = errorStatus
    response.entity = json(object(field("error", errorMessage)))
    return response
}

