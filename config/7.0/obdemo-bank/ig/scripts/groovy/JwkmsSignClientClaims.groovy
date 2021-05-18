import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*


import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import java.security.PrivateKey

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

import groovy.json.JsonSlurper


logger.debug("Signing claims as ApiClient")


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
    logger.error("No client certificate for signing claims")
    return new Response(Status.BAD_REQUEST)
}

if (!attributes.clientCertificate.privateKey) {
    logger.error("No private key in cert")
    return new Response(Status.BAD_REQUEST)
}

def optionsHeaders = request.headers.get(routeArgOptionsHeader)

def signingOptions = []

if (optionsHeaders != null) {

    String optionsJson = URLDecoder.decode(optionsHeaders.firstValue.toString())
    logger.debug("Got options header " + optionsJson)
    def slurper = new JsonSlurper()
    signingOptions = slurper.parseText(optionsJson)
    if (signingOptions == null) {
        logger.error("Couldn't parse signing options")
        return new Response(Status.BAD_REQUEST)
    }
}


PrivateKey signingKey = attributes.clientCertificate.privateKey;

logger.debug("Recovered private key {}",signingKey)

def jwt = ""
def isDetached = (signingOptions && signingOptions.detachedsig == true)
def kid = attributes.clientCertificate.serialNumber.toString()

if (signingOptions.unencodedpayload) {

    Payload detachedPayload = new Payload(request.entity.getString());

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256)
            .base64URLEncodePayload(false)
            .criticalParams(Collections.singleton("b64"))
            .keyID(kid)
            .build();

    JWSObject jwsObject = new JWSObject(header, detachedPayload);
    // jwsObject.sign(new MACSigner(hmacJWK));
    jwsObject.sign(new RSASSASigner(signingKey));

    jwt = jwsObject.serialize(isDetached);
}
else {
    def jwtClaims = new JwtClaimsSet(request.entity.getJson())

    SigningHandler signingHandler = new SigningManager().newRsaSigningHandler(signingKey);



    jwt = new JwtBuilderFactory()
            .jws(signingHandler)
            .headers()
            .alg(JwsAlgorithm.PS256)
            .kid(kid)
            .done()
            .claims(jwtClaims)
            .build();

    if (isDetached) {
        String[] jwtElements = jwt.split("\\.")

        if (jwtElements.length != 3) {
            logger.error("Wrong number of dots on generated jwt " +  jwt.length)
            Response response = new Response(Status.INTERNAL_SERVER_ERROR)
            return response
        }

        jwt = jwtElements[0] + ".." + jwtElements[2]

        logger.debug("Removed payload - now {}",jwt)
    }
}

logger.debug("Generated jwt {}", jwt)



Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","text/plain");
response.setEntity(jwt);

return response






