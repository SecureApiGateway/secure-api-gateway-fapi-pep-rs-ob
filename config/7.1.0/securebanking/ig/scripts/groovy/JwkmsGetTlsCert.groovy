import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.JWKSet
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import java.security.*;
import java.security.cert.X509Certificate
import java.io.StringWriter;

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[JwkmsGetTlsCert] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def getTlsKey(jwks) {
    List<RSAKey> jwkKeys = jwks.getKeys();

    def key = null;

    jwkKeys.forEach(k -> {
        def use = k.getKeyUse().identifier();
        logger.debug(SCRIPT_NAME + "Key use " + use);
        if (use == "tls") {
            logger.debug(SCRIPT_NAME + "Found TLS key " + k);
            key = k;
        }
    });

    return key;
}

JWKSet jwks = JWKSet.parse(request.entity.getString());

if (!jwks) {
    logger.error(SCRIPT_NAME + "Couldn't parse request body as JWK set");
    return new Response(Status.BAD_REQUEST);
}

RSAKey jwk = getTlsKey(jwks);

if (!jwk) {
    logger.error(SCRIPT_NAME + "Couldn't find TLS key in JWK set");
    return new Response(Status.BAD_REQUEST);
}

PrivateKey privateKey = jwk.toPrivateKey();

if (!privateKey) {
    logger.error(SCRIPT_NAME + "Couldn't find private key in tls jwk");
    return new Response(Status.BAD_REQUEST);
}

List<X509Certificate> certChain = jwk.getParsedX509CertChain();

if (!certChain) {
    logger.error(SCRIPT_NAME + "Couldn't find cert chain in tls jwk");
    return new Response(Status.BAD_REQUEST);
}

def pemify(obj) {
    StringWriter writer = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
    pemWriter.writeObject(obj);
    pemWriter.flush();
    pemWriter.close();

    return writer.toString();
}

def certPem = "";
certChain.forEach(cert -> { certPem = certPem.concat(pemify(cert))});
def keyPem  = pemify(privateKey);

Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","text/plain");
response.setEntity(certPem + keyPem);

return response
