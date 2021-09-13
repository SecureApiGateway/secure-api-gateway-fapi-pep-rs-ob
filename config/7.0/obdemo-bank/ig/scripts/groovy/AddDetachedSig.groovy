import org.forgerock.secrets.keys.SigningKey
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.secrets.Purpose
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.http.protocol.Status
import org.forgerock.http.protocol.Response

/*
 * Add detached signature to HTTP response
 *
 * Detached signature is signed JWT with response entity as payload
 * JWT is added as response header, with payload removed
 *
 * Can be replaced with JwtBuilderFilter if/when it can be used as a response filter
 *
 */


next.handle(context, request).thenOnResult({ response ->

  // response object
  response = new Response(Status.OK)
  response.headers['Content-Type'] = "application/json"

  JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(routeArgAlgorithm)

  Purpose<SigningKey> purpose = new JsonValue(routeArgSecretId).as(purposeOf(SigningKey.class))

  SigningManager signingManager = new SigningManager(routeArgSecretsProvider)
  signingManager.newSigningHandler(purpose).then({ signingHandler ->

    JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(response.getEntity().getJson())


    String jwt = new JwtBuilderFactory()
            .jws(signingHandler)
            .headers()
            .alg(signAlgorithm)
            .kid(routeArgKid)
            .done()
            .claims(jwtClaimsSet)
            .build()

    logger.debug("Signed JWT [" + jwt + "]")

    if (jwt == null || jwt.length() == 0) {
      message = "Error creating signature JWT"
      logger.error(message)
      response.status = Status.INTERNAL_SERVER_ERROR
      response.entity = "{ \"error\":\"" + message + "\"}"
      return response
    }

    String[] jwtElements = jwt.split("\\.")

    if (jwtElements.length != 3) {
      message = "Wrong number of dots on outbound detached signature"
      logger.error(message)
      response.status = Status.INTERNAL_SERVER_ERROR
      response.entity = "{ \"error\":\"" + message + "\"}"
      return response
    }

    String detachedSig = jwtElements[0] + ".." + jwtElements[2]

    logger.debug("Adding detached signature [" + detachedSig + "]")

    response.getHeaders().add(routeArgHeaderName,detachedSig);


    return response

  })

})
