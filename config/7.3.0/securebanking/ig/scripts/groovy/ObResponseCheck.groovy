import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import groovy.json.JsonSlurper


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

String HEADER_INTERACTION_ID = "x-fapi-interaction-id"
Map<String, String> getGenericError(Status status, String responseBody, boolean isV4Request) {

  String errorCode
  String message
  logger.debug(SCRIPT_NAME + "STATUS-*-: " + status)
  logger.debug(SCRIPT_NAME + "ERROR-*- body: " + responseBody)
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

  if (responseBody) {
    def slurper = new JsonSlurper()
    Map responseObj = slurper.parseText(responseBody)
    logger.debug(SCRIPT_NAME + "Response error from backend: " + responseObj)
    if(responseObj.Code){
      errorCode = responseObj.Errors[0].ErrorCode
      message = responseObj.Errors[0].Message
      path = responseObj.Errors[0].Path
      if (path) {
        return [
                ErrorCode: errorCode,
                Message: message,
                Path: path
        ]
      }
    }
    if (responseObj.error) {
      message += " [" + responseObj.error + "]"
    }
    if (responseObj.error_description) {
      message += " [" + responseObj.error_description + "]"
    }
    logger.debug(SCRIPT_NAME + "Response values errorCode= " + errorCode + ", message= " + message)
  }

  return [
          ErrorCode: errorCode,
          Message: message
  ]
}

// Placeholder right now - always assume that we don't have an OB compliant response already
//
// TODO: parse response body to see if already OB compliant response

static isObCompliantError(responseBody) {
  return false
}

def v4Request = (request.uri.pathElements.size() > 2) && request.uri.pathElements[2].startsWith("v4")

next.handle(context, request).thenOnResult({response ->

  // Check for OB compliant error response

  Status status = response.getStatus()
  String responseBody = response.getEntity().getString();

  // Build an OBErrorResponse1 response object
  if ((status.isClientError() || status.isServerError()) && !isObCompliantError(responseBody)) {

    def code = status.getCode()
    def reason = response.getCause()

    Map<String,String> newBody = [
            Code: code.toString()
    ]

    requestIds = request.headers.get("x-request-id")
    if (requestIds) {
      newBody.put("Id",requestIds.firstValue)
    }

    newBody.put("Message",  status.toString())

    def obErrorObject = getGenericError(status, responseBody, v4Request)
    errorList = [obErrorObject]
    newBody.put("Errors", errorList)
    logger.debug(SCRIPT_NAME + "Final Error Response: " + newBody)
    response.setEntity(newBody)
  }
})

