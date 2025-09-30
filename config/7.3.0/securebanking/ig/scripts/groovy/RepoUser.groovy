import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.http.protocol.Status.BAD_REQUEST
import static org.forgerock.http.protocol.Status.NOT_FOUND
import static org.forgerock.http.protocol.Status.OK
import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import static org.forgerock.util.Closeables.closeSilently
import static org.forgerock.openig.util.JsonValues.listOf

import org.forgerock.util.promise.NeverThrowsException
import org.forgerock.json.JsonValue


/**
 * Scripted Handler implementation to retrieve user details from the user repo, by query or specific user ID.
 *
 * Examples to test the filter. It needs to be run from a container:
 * - curl -i -v http://ig:80/repo/users?_queryFilter=userName+eq+%22<Cloud platform user name>%22
 * - curl -i -v http://ig:80/repo/users/<Cloud platform user ID>
 */

// FAPI logging
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[RepoUser] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

return handle(context, request)

/**
 * Fetch the API client from the repo.
 * @param unusedContext Context is unused
 * @param request Request to obtain repo user
 * @param unusedNext Next handler is unused due to how this is configured in the route
 * @return Promise of a Response containing user details
 */
Promise<Response, NeverThrowsException> handle(final Context unusedContext, final Request request) {
    // Get raw URI query filter (encoded to avoid illegal character in query) and obtain path elements
    def uriQuery = request.uri.getRawQuery()
    def uriPathElements = request.uri.getPathElements()
    logger.debug(SCRIPT_NAME + "uriQuery: {}, uriPathElements: {}", uriQuery, uriPathElements)
    if (uriPathElements.isEmpty()) {
        return newResponsePromise(
                fail(BAD_REQUEST,
                     "Not elements found in the uri path, uri path elements is empty from inbound request"))
    }

    // Fetch the User from IDM
    Request userRequest = new Request();
    userRequest.setMethod('GET');
    def userRequestUri = null
    boolean isQuery = false
    // Condition IDM request to retrieve the user data by user name or by user ID
    if (Objects.nonNull(uriQuery)) {
        logger.debug(SCRIPT_NAME + "Looking up API User by filter {}", uriQuery)
        userRequestUri = routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjUser + "?" + uriQuery
        isQuery = true
    } else {
        logger.debug(SCRIPT_NAME + "Looking up API User by user ID {}", uriPathElements[ uriPathElements.size() - 1 ])
        userRequestUri = routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjUser + "/" + uriPathElements[
                uriPathElements.size() - 1 ]
    }
    userRequest.setUri(userRequestUri)

    logger.debug(SCRIPT_NAME + "Obtaining User data from repo {}", userRequestUri)
    return http.send(userRequest)
               .thenAlways(() -> closeSilently(userRequest))
               .thenAsync(userResponse -> handleUserResponse(userResponse, isQuery))
}

private Promise<Response, NeverThrowsException> handleUserResponse(Response userResponse, boolean isQuery) {
    logger.debug(SCRIPT_NAME + "Handling user response")
    return processResponseContent(userResponse)
            .thenAlways(() -> closeSilently(userResponse))
            .then(apiClientResponseJson -> transformApiClientResponse(apiClientResponseJson, isQuery),
                  exception -> {
                      fail(apiClientResponseStatus, exception.getMessage())
                  })
}

private Promise<JsonValue, Exception> processResponseContent(final Response userResponse) {
    if (!(OK.equals(userResponse.getStatus()))) {
        logger.error("Unable to communicate with User endpoint - status code {}",
                     userResponse.getStatus().getCode())
        return newExceptionPromise(
                new IOException("Failed to get User details - problem communicating with repo"))
    }
    ContentTypeHeader contentTypeHeader = ContentTypeHeader.valueOf(userResponse)
    String contentType = contentTypeHeader != null ? contentTypeHeader.getType() : null
    if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
        logger.error("API client endpoint response has unexpected content-type {}", contentType)
        return newExceptionPromise(
                new IOException("Failed to get API Client details - unexpected content " + contentType))
    }
    return getJsonContentAsync(userResponse)
}

private static Promise<JsonValue, Exception> getJsonContentAsync(final Response response) {
    return response.getEntity()
                   .getJsonAsync()
                   .then(jsonContent -> new JsonValue(jsonContent).expect(Map.class))
                   .thenCatch(exception -> {
                       throw new IOException("Evaluation response has malformed response JSON");
                   })
}

private Response transformApiClientResponse(JsonValue userResponseJson, boolean isQuery) {
    JsonValue userResponseJson2 = userResponseJson
    if (isQuery) {
        if (userResponseJson.get("result").isEmpty()) {
            return fail(NOT_FOUND, "User details not found")
        }
        userResponseJson2 = userResponseJson.get("result").as(listOf(JsonValue::asString).get(0))
    }
    JsonValue transformedResponseJson = json(object(
            field("id", userResponseJson2.get("_id")),
            field("userName", userResponseJson2.get("userName")),
            field("givenName", userResponseJson2.get("givenName")),
            field("surname", userResponseJson2.get("sn")),
            field("mail", userResponseJson2.get("mail")),
            field("accountStatus", userResponseJson2.get("accountStatus"))))
    logger.debug(SCRIPT_NAME + "Transformed JSON {}", transformedResponseJson)
    Response transformedResponse = new Response(OK)
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
