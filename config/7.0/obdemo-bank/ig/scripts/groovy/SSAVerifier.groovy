import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.http.protocol.Status;
import java.net.URI;

def verifySignature(signedJwt,jwksJson) {

    if (!signedJwt) {
        logger.error("Failed to reconstruct JWT")
        return false;
    }

    def kid = signedJwt.getHeader().getKeyId();

    if (!kid) {
        logger.error("Couldn't find kid in jwt header")
        return false;
    }

    def jwks = JWKSet.parse(jwksJson);

    if (!jwks) {
        logger.error("Failed to parse JWKS")
        return false;
    }

    def jwk = jwks.findJwk(kid);

    if (!jwk) {
        logger.error("Could jwk with kid {} in JWKS",kid)
        return false;
    }

    def publicKey = jwk.toRSAPublicKey();

    if (!publicKey) {
        logger.error("Couldn't get RSA public key from JWKS entry for kid {}",kid);
        return false;
    }

    def verificationHandler = new SigningManager().newRsaSigningHandler(publicKey);
    def signatureVerified = signedJwt.verify(verificationHandler);

    logger.debug("Signature verified: {}",signatureVerified);

    return signatureVerified;
}

def errorResponse(httpCode, message) {
    logger.error("Returning error " + httpCode + ": " + message);
    def response = new Response(httpCode)
    response.headers['Content-Type'] = "application/json"
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response;
}

def method = request.method

switch(method.toUpperCase()) {

    case "POST":

    if (!attributes.registrationJWTs) {
        return(errorResponse(Status.UNAUTHORIZED,"No registration JWT"));
    }

    def ssaJwt = attributes.registrationJWTs.ssaJwt;

    if (!ssaJwt) {
        return(errorResponse(Status.UNAUTHORIZED,"No SSA JWT"));
    }

    if (!routeArgSSAIssuerJwksUrls) {
        return(errorResponse(Status.INTERNAL_SERVER_ERROR,"No configured JWKS URIs"));
    }

    def ssaClaims = ssaJwt.getClaimsSet();

    def ssaIssuer = ssaClaims.getIssuer();

    if (!ssaIssuer) {
        return(errorResponse(Status.UNAUTHORIZED,"SSA has no issuer"));
    }

    def ssaJwksUrl = routeArgSSAIssuerJwksUrls[ssaIssuer];

    if (!ssaJwksUrl) {
        return(errorResponse(Status.UNAUTHORIZED,"Unknown SSA issuer: " + ssaIssuer));
    }

    def ssaJwksUri = null;

    try {
        ssaJwksUri = new URI(ssaJwksUrl);
    }
    catch (e) {
        return(errorResponse(Status.INTERNAL_SERVER_ERROR,"Error parsing JWKS URL " + ssaJwksUrl + "(" + e + ")"));
    }

    logger.debug("Validating SSA JWT - Issuer {}, JWKS URI {}",ssaIssuer,ssaJwksUrl);

    Request jwksRequest = new Request();


    jwksRequest.setMethod('GET');
    jwksRequest.setUri(ssaJwksUrl);
    // jwksRequest.getHeaders().add("Host",ssaJwksUri.getHost());


    http.send(jwksRequest).then(jwksResponse -> {

      jwksRequest.close();
      logger.debug("Back from JWKS URI");
      def jwksResponseContent = jwksResponse.getEntity().getString();
      def jwksResponseStatus = jwksResponse.getStatus();

      logger.debug("status " + jwksResponseStatus);
      logger.debug("entity " + jwksResponseContent);

      if (jwksResponseStatus != Status.OK) {
          return(errorResponse(Status.UNAUTHORIZED,"Bad response from JWKS URI " + jwksResponseStatus));
      }
      else if (!verifySignature(ssaJwt,jwksResponseContent)) {
          return(errorResponse(Status.UNAUTHORIZED,"Signature not verified"));
      }

      return null;
    }).thenAsync (error -> {
      if (error) {
          // TODO: This doesn't work - get cast error from Response to Promise
          logger.error("Sending back error response");
          return error;
      }
      next.handle(context, request);
    });
    break

    case "DELETE":
       break
    default:
        logger.debug("Method not supported")

}


next.handle(context, request)

