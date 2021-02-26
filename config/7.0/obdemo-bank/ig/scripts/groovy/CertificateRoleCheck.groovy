import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

// Check transport certificate for roles appropriate to request


logger.debug("Checking certificate roles for {} request",routeArgRole)

def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
  logger.error("No client certificate for TPP role check")
  return new Response(Status.BAD_REQUEST)
}


def roles = attributes.clientCertificate.roles
if (!roles) {
  logger.error("No roles in client certificate for TPP role check")
  return new Response(Status.BAD_REQUEST)
}

// Check certificate role based on request type



if (routeArgRole == "AISP" && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
  logger.error("Role AISP requires certificate role {}",
          ROLE_ACCOUNT_INFORMATION
  )
  return new Response(Status.FORBIDDEN)
}
else if (routeArgRole == "PISP" && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
  logger.error("Role PISP requires certificate role {}",
          ROLE_PAYMENT_INITIATION
  )
  return new Response(Status.FORBIDDEN)
}


next.handle(context, request)






