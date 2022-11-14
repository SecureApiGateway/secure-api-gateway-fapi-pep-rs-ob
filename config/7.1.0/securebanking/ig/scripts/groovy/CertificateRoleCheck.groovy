import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*

// Check transport certificate for roles appropriate to request
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[CertificateRoleCheck] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Checking certificate roles for {} request",routeArgRole)

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
  message = "No client certificate for TPP role check"
  logger.error(SCRIPT_NAME + message)
  response.status = Status.BAD_REQUEST
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}


def roles = attributes.clientCertificate.roles
if (!roles) {
  message = "No roles in client certificate for TPP role check"
  logger.error(SCRIPT_NAME + message)
  response.status = Status.BAD_REQUEST
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}

// Check certificate role based on request type



if (routeArgRole == "AISP" && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
  message = "Role AISP requires certificate role " + ROLE_ACCOUNT_INFORMATION
  logger.error(SCRIPT_NAME + message)
  response.status = Status.FORBIDDEN
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}
else if (routeArgRole == "PISP" && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
  message = "Role PISP requires certificate role " + ROLE_PAYMENT_INITIATION
  logger.error(SCRIPT_NAME + message)
  response.status = Status.FORBIDDEN
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}


next.handle(context, request)






