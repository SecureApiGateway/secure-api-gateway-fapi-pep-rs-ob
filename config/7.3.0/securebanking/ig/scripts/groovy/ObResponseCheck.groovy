import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.openig.util.JsonValues.listOf

import org.forgerock.http.protocol.Status
import org.forgerock.util.promise.NeverThrowsException
import org.forgerock.json.JsonValue

/*
 * Script to set entity to OB compliant response headers and body
 *
 * Ensure response header has interaction ID
 *
 * Ensure that response body is OB compliant on error
 *
 * If not HTTP error response, then allow through
 * If HTTP error response with OB error message (i.e. from RS), then allow through
 * If HTTP error response and OB error in shared state (i.e. from IG), then set response entity to OB error
 * If HTTP error response with no OB error in shared state, set response body to generic OB error
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ObResponseCheck] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

// Perform error response compliance checks
return filter(context, request, next)

/**
 * Filter implementation to enforce Open Banking standard error responses.
 * @param context the Context
 * @param request the request
 * @param next the next Handler
 * @return Promise of the downstream Response
 */
Promise<Response, NeverThrowsException> filter(final Context context,
                                               final Request request,
                                               final Handler next) {
    return next.handle(context, request)
               .thenAsync(response -> {
                   Status status = response.getStatus()
                   if (status.isSuccessful()) {
                       return newResponsePromise(response)
                   }
                   boolean isV4Request = (request.uri.pathElements.size() > 2)
                           && request.uri.pathElements[2].startsWith("v4")
                   return enforceOpenBankingCompliance(response, isV4Request)
               })
               .thenCatch(exception -> newInternalServerError(exception))
}

/* Check for OB compliant error response.
 */
private Promise<Response, Exception> enforceOpenBankingCompliance(Response response, boolean isV4Request) {
    return response.getEntity().getJsonAsync()
                   .then(jsonContent -> new JsonValue(jsonContent).expect(Map.class))
                   .then(responseJson -> {
                       if (isObCompliantError(responseJson)) {
                           return response
                       }
                       // Build an OBErrorResponse1 response object
                       Status status = response.getStatus()
                       def code = status.getCode()
                       def reason = response.getCause()
                       Map<String, Object> transformedObErrorResponseBody = [
                               Code: code.toString()
                       ]
                       requestIds = request.headers.get("x-request-id")
                       if (requestIds) {
                           transformedObErrorResponseBody.put("Id", requestIds.firstValue)
                       }
                       transformedObErrorResponseBody.put("Message", status.toString())

                       def obErrorObject = getGenericError(status, (JsonValue) responseJson, isV4Request)
                       errorList = [ obErrorObject ]
                       transformedObErrorResponseBody.put("Errors", errorList)
                       logger.debug(SCRIPT_NAME + "error-code: {}, reason: {}, transformed error response: {}",
                                    code,
                                    reason,
                                    transformedObErrorResponseBody)
                       response.setEntity(transformedObErrorResponseBody)
                       return response
                   })
}

/* Placeholder right now - always assume that we don't have an OB compliant response already
 *
 * TODO: parse response body to see if already OB compliant response
 */
private static boolean isObCompliantError(responseBody) {
    return false
}

/*
 * Convert response error payload to OB JSON (Map) format.
 */
private Map<String, String> getGenericError(Status status, JsonValue responseJson, boolean isV4Request) {
    String errorCode
    String message
    logger.debug(SCRIPT_NAME + "STATUS-*-: {}", status)
    logger.debug(SCRIPT_NAME + "ERROR-*- body: {}", responseJson)

    switch (status) {
    case Status.NOT_FOUND:
        errorCode = isV4Request ? "U011" : "UK.OBIE.NotFound"
        message = isV4Request ? "Resource cannot be found" : "Resource not found"
        break
    case Status.BAD_REQUEST:
        errorCode = isV4Request ? "U002" : "UK.OBIE.Field.Invalid"
        message = isV4Request ? "Field is invalid" : "Bad request"
        break
    case Status.UNAUTHORIZED:
        errorCode = "UK.OBIE.Unauthorized"
        message = "Unauthorized"
        break
    case Status.FORBIDDEN:
        errorCode = isV4Request ? "U028" : "UK.OBIE.Reauthenticate"
        message = isV4Request ? "Reauthentication is required by PSU" : "Forbidden"
        break
    case Status.INTERNAL_SERVER_ERROR:
        errorCode = isV4Request ? "U000" : "UK.OBIE.UnexpectedError"
        message = "Internal error"
        break
    default:
        errorCode = isV4Request ? "U000" : "UK.OBIE.UnexpectedError"
        message = "Internal error"
    }

    if (responseJson != null && !responseJson.isNull()) {
        logger.debug(SCRIPT_NAME + "Response error from backend: {}", responseJson)
        if (responseJson.isDefined("Code")) {
            List<Map<String, String>> responseErrors = responseJson.get("Errors").as(listOf(JsonValue::asMap))
            if (!responseErrors.isEmpty()) {
                def responseError0 = responseErrors.get(0)
                errorCode = responseError0.get("ErrorCode")
                message = responseError0.get("Message")
                path = responseError0.get("Path")
                if (path != null) {
                    return [
                            ErrorCode: errorCode,
                            Message  : message,
                            Path     : path
                    ]
                }
            } else {
                logger.debug(SCRIPT_NAME + "Response 'Errors' list unexpectedly empty when 'Code' present")
            }
        }
        if (responseJson.isDefined("error")) {
            message += " [" + responseJson.get("error").asString() + "]"
        }
        if (responseJson.isDefined("error_description")) {
            message += " [" + responseJson.get("error_description").asString() + "]"
        }
        logger.debug(SCRIPT_NAME + "Response values errorCode={}, message={}", errorCode, message)
    } else {
        logger.debug(SCRIPT_NAME + "Response error has no content")
    }
    return [
            ErrorCode: errorCode,
            Message  : message
    ]
}

