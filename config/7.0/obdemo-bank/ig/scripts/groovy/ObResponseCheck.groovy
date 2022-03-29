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

String HEADER_INTERACTION_ID = "x-fapi-interaction-id"


Map<String, String> getGenericError(Status status, String responseBody) {

  String errorCode
  String message
  logger.debug("STATUS-*-: " + status)
  logger.debug("ERROR-*- body: " + responseBody)
  switch (status) {

    case Status.NOT_FOUND:
         errorCode = "UK.OBIE.NotFound"
         message = "Resource not found"
         break

    case Status.BAD_REQUEST:
      errorCode = "UK.OBIE.Field.Invalid"
      message = "Bad request"
      break

    case Status.UNAUTHORIZED:
      errorCode = "UK.OBIE.Unauthorized"
      message = "Unauthorized"
      break

    case Status.FORBIDDEN:
      errorCode = "UK.OBIE.Reauthenticate"
      message = "Forbidden"
      break

    case Status.INTERNAL_SERVER_ERROR:
      errorCode = "UK.OBIE.UnexpectedError"
      message = "Internal error"
      break

    default:
      errorCode = "UK.OBIE.UnexpectedError"
      message = "Internal error"
  }

  if (responseBody) {
    def slurper = new JsonSlurper()
    Map responseObj = slurper.parseText(responseBody)
    logger.debug("Response error from backend: " + responseObj)
    if(responseObj.Code){
      errorCode = responseObj.Errors[0].ErrorCode
      message = responseObj.Errors[0].Message
    }
    if (responseObj.error) {
      message += " [" + responseObj.error + "]"
    }
    if (responseObj.error_description) {
      message += " [" + responseObj.error_description + "]"
    }
    logger.debug("Response values errorCode= " + errorCode + ", message= " + message)
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

void bounceBackHeader(Request req, Response rsp, String headerName, boolean createIfAbsent) {
  String val = null
  inboundValues = req.headers.get(headerName)
  if (inboundValues == null && createIfAbsent) {
    logger.debug("No inbound header value - creating one")
    val = UUID.randomUUID().toString();
  }
  else {
    val = inboundValues.firstValue;
  }

  if (val) {
    rsp.headers.add(headerName, val)
  }

}

next.handle(context, request).thenOnResult({response ->

  // Check for FAPI interaction ID

  bounceBackHeader(request,response,HEADER_INTERACTION_ID,true)

  // Check for OB compliant error response

  Status status = response.getStatus()
  String responseBody = response.getEntity().getString();

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

    Map<String,String> errorList = attributes.obErrors

    if (!errorList) {
      errorList = getGenericError(status,responseBody)
    }

    newBody.put("Errors",errorList)
    logger.debug("Final Error Response: " + newBody)
    response.setEntity(newBody)
  }
})









