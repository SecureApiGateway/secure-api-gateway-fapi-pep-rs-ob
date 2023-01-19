import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.http.protocol.Status;
import java.net.URI;
import java.security.SignatureException
import com.securebanking.gateway.dcr.ErrorResponseFactory
import static org.forgerock.util.promise.Promises.newResultPromise
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[SSAVerifier] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")


if(trustedDirectoryService == null) {
    logger.error(SCRIPT_NAME + "No TrustedDirectoriesService defined on the heap in config.json")
    return new Response(Status.INTERNAL_SERVER_ERROR).body("No TrustedDirectoriesService defined on the heap in config.json")
}

def verifySignature(signedJwt, jwksJson) {
    def jwks = JWKSet.parse(jwksJson);
    try {
        jwtSignatureValidator.validateSignature(signedJwt, jwks)
        return true
    } catch (SignatureException se) {
        logger.warn(SCRIPT_NAME + "jwt signature validation failed", se)
        return false
    }
}

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def method = request.method
switch(method.toUpperCase()) {
    case "POST":
    case "PUT":
        if (!attributes.registrationJWTs) {
            return errorResponseFactory.errorResponse(Status.UNAUTHORIZED, "No registration JWT")
        }

        def ssaJwt = attributes.registrationJWTs.ssaJwt
        if (!ssaJwt) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No SSA JWT")
        }

        def ssaClaims = ssaJwt.getClaimsSet()
        def ssaIssuer = ssaClaims.getIssuer()
        if (!ssaIssuer) {
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("issuer claim is required")
        }

        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer)
        if(trustedDirectory){
            logger.debug(SCRIPT_NAME + "Found trusted directory for issuer '" + ssaIssuer + "'")
        } else {
            logger.debug(SCRIPT_NAME + "Could not find Trusted Directory for issuer '" + ssaIssuer + "'")
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("issuer: " + ssaIssuer + " is not supported")
        }

        def ssaJwksUrl = trustedDirectory.getDirectoryJwksUri()
        if (!ssaJwksUrl) {
            return errorResponseFactory.invalidSoftwareStatementErrorResponse("issuer: " + ssaIssuer + " is not supported")
        }

        logger.debug(SCRIPT_NAME + "Validating SSA JWT - Issuer {}, JWKS URI {}", ssaIssuer, ssaJwksUrl)

        Request jwksRequest = new Request()
        jwksRequest.setMethod('GET')
        jwksRequest.setUri(ssaJwksUrl.toString())
        return http.send(jwksRequest).thenAsync(jwksResponse -> {
          jwksRequest.close()
          logger.debug(SCRIPT_NAME + "Back from JWKS URI")
          def jwksResponseContent = jwksResponse.getEntity().getString()
          def jwksResponseStatus = jwksResponse.getStatus()

          logger.debug(SCRIPT_NAME + "status " + jwksResponseStatus)
          logger.debug(SCRIPT_NAME + "entity " + jwksResponseContent.replaceAll("[\\n\\t ]", ""))

          if (jwksResponseStatus != Status.OK) {
              return newResultPromise(errorResponseFactory.errorResponse(Status.UNAUTHORIZED, "Bad response from JWKS URI " + jwksResponseStatus))
          }
          else if (!verifySignature(ssaJwt, jwksResponseContent)) {
              return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse("software_statement signature is invalid"))
          }
          return next.handle(context, request)
        })

    case "DELETE":
    case "GET":
        return next.handle(context, request)
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return new Response(Status.METHOD_NOT_ALLOWED)
}
