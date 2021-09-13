import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*
import groovy.json.JsonSlurper

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

// response object
response = new Response(Status.BAD_REQUEST)
response.headers['Content-Type'] = "application/json"

def validateUnencodedPayload(jws, payload) {
    Payload detachedPayload = new Payload(payload);
    JWSObject parsedJWSObject = JWSObject.parse(jws, detachedPayload);
    JWKSet jwkSet
    try {
        jwkSet = JWKSet.load(new URL(routeArgJwkUrl))
    }
    catch (e) {
        logger.error("Exception getting JWK set; {}",e)
        return false
    }

    JWSHeader jwsHeader = parsedJWSObject.getHeader();
    List<JWK> matches = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader))
            .select(jwkSet);


    if (matches.size() != 1) {
        logger.error("Unexpected number of matching JWKs - {}",matches.size())
        return false
    }

    RSAKey rsaPublicJWK = matches.get(0).toPublicJWK();

    logger.debug("Got public key {}",rsaPublicJWK)

    JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
    return parsedJWSObject.verify(verifier)
}

// On the way in, build a JWT from the header and content to pass to the JWT verification filter
//
// Subject to waiver for earlier versions as per
// https://openbanking.atlassian.net/wiki/spaces/DZ/pages/1112670669/W007
//
// If ASPSPs are still using v3.1.3 or earlier, they must support the parameter b64 to be false,
// and any TPPs using these ASPSPs must do the same.
//
// If ASPSPs have updated to v3.1.4 or later, they must not include the b64 claim in the header,
// and any TPPs using these ASPSPs must do the same.

def splitPath = request.uri.path.split("/")

if (splitPath.length < 2) {
    message = "Can't parse API version for inbound request"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def apiVersion = splitPath[splitPath.length - 2]


logger.debug("Building JWT from detached header")

logger.debug("API version " + apiVersion)



def header = request.headers.get(routeArgHeaderName)

if (header == null) {
    message = "No detached signature header on inbound request " + routeArgHeaderName
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String detachedSig = header.firstValue.toString()

logger.debug("Inbound detached sig " + detachedSig)
String[] sigElements = detachedSig.split("\\.")

if (sigElements.length != 3) {
    message = "Wrong number of dots on inbound detached signature " +  sigElements.length
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String jwtHeader      = sigElements[0]
String jwtSignature   = sigElements[2]

// Check JWT header for b64 claim
//
// If claim is present, and API version > 3.1.3 then reject
// If claim is present, and is set to false, and API < 3.1.4 then accept and validate as non base64 payload

String headerJson = new String(jwtHeader.decodeBase64Url())
logger.debug("Got JWT header " + headerJson)
JsonSlurper slurper = new JsonSlurper()
def headerObj = slurper.parseText(headerJson)

String jwtPayload = null


if (headerObj.b64 != null && apiVersion > "v3.1.3") {
    message = "B64 header not permitted in JWT header after 3.1.3"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}
else if (headerObj.b64 != null && headerObj.b64 == false) {
    logger.debug("Unencoded payload")
    jwtPayload     = request.entity.getString()
    attributes.encodedPayload = false
    if (!validateUnencodedPayload(detachedSig,jwtPayload)) {
        message = "Signature validation failed"
        logger.error(message)
        response.status = Status.UNAUTHORIZED
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }
    logger.debug("Detached signature verified against unencoded payload")
}
else {
    logger.debug("Standard base64 encoded payload for detached sig")
    jwtPayload     = request.entity.bytes.encodeBase64Url().toString()
    attributes.encodedPayload = true
    String jwt = jwtHeader + "." + jwtPayload + "." + jwtSignature

    logger.debug("Constructed JWT " + jwt)

    attributes.detachedJWT = jwt
}


next.handle(context,request)

