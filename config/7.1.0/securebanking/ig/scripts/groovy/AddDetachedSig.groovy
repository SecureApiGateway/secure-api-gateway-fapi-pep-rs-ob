import org.forgerock.secrets.keys.SigningKey
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.secrets.Purpose
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.http.protocol.Status

/**
 * Add detached signature to HTTP response
 *
 * Detached signature is signed JWT with response entity as payload
 * JWT is added as response header, with payload removed
 *
 * Can be replaced with JwtBuilderFilter if/when it can be used as a response filter
 *
 */

SCRIPT_NAME = "[AddDetachedSig] - "
IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"

next.handle(context, request).thenOnResult({ response ->
    logger.debug(SCRIPT_NAME + "Running...")
    logger.debug(SCRIPT_NAME + "routeArgSecretId: " + routeArgSecretId)
    logger.debug(SCRIPT_NAME + "routeArgKid: " + routeArgKid)

    JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(routeArgAlgorithm)
    logger.debug(SCRIPT_NAME + "Algorithm initialised: " + signAlgorithm)

    Purpose<SigningKey> purpose = new JsonValue(routeArgSecretId).as(purposeOf(SigningKey.class))

    SigningManager signingManager = new SigningManager(routeArgSecretsProvider)

    signingManager.newSigningHandler(purpose).then({ signingHandler ->
        logger.debug(SCRIPT_NAME + "Building of the JWT started")

        JwtClaimsSet jwtClaimsSet
        // We get content empty on submit file payment API
        if (response.getEntity().isRawContentEmpty()) {
            jwtClaimsSet = new JwtClaimsSet()
        } else {
            jwtClaimsSet = new JwtClaimsSet(response.getEntity().getJson())
        }
        logger.debug(SCRIPT_NAME + "jwtClaimsSet: " + jwtClaimsSet)

        List<String> critClaims = new ArrayList<String>();
        critClaims.add(IAT_CRIT_CLAIM);
        critClaims.add(ISS_CRIT_CLAIM);
        critClaims.add(TAN_CRIT_CLAIM);

        //TODO - http://openbanking.org.uk/iss must be extracted from the OB signing certificate of the ASPSP. Currently we don't have open banking certificates on ASPSP side
        String jwt
        try {
            jwt = new JwtBuilderFactory()
                    .jws(signingHandler)
                    .headers()
                    .alg(signAlgorithm)
                    .kid(routeArgKid)
                    .header(IAT_CRIT_CLAIM, System.currentTimeMillis() / 1000)
                    .header(ISS_CRIT_CLAIM, "CN=0015800001041REAAY,organizationIdentifier=PSDGB-OB-Unknown0015800001041REAAY,O=FORGEROCK LIMITED,C=GB")
                    .header(TAN_CRIT_CLAIM, routeArgTrustedAnchor)
                    .crit(critClaims)
                    .done()
                    .claims(jwtClaimsSet)
                    .build()
        } catch (java.lang.Exception e) {
            logger.debug(SCRIPT_NAME + "Error building JWT: " + e)
        }

        logger.debug(SCRIPT_NAME + "Signed JWT [" + jwt + "]")

        if (jwt == null || jwt.length() == 0) {
            message = "Error creating signature JWT"
            logger.error(SCRIPT_NAME + message)
            response.status = Status.INTERNAL_SERVER_ERROR
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        String[] jwtElements = jwt.split("\\.")

        if (jwtElements.length != 3) {
            message = "Wrong number of dots on outbound detached signature"
            logger.error(SCRIPT_NAME + message)
            response.status = Status.INTERNAL_SERVER_ERROR
            response.entity = "{ \"error\":\"" + message + "\"}"
            return response
        }

        String detachedSig = jwtElements[0] + ".." + jwtElements[2]
        logger.debug(SCRIPT_NAME + "Adding detached signature [" + detachedSig + "]")

        response.getHeaders().add(routeArgHeaderName, detachedSig);
        return response
    })
})
