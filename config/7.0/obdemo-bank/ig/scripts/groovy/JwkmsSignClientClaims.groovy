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

def jwtClaims = new JwtClaimsSet(request.entity.getJson())

PrivateKey signingKey = attributes.clientCertificate.privateKey;

logger.debug("Recovered private key {}",signingKey)

SigningHandler signingHandler = new SigningManager().newRsaSigningHandler(signingKey);

def kid = attributes.clientCertificate.serialNumber.toString()

def jwt = new JwtBuilderFactory()
                .jws(signingHandler)
                .headers()
                .alg(JwsAlgorithm.PS256)
                .kid(kid)
                .done()
                .claims(jwtClaims)
                .build();

Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","text/plain");
response.setEntity(jwt);

return response






