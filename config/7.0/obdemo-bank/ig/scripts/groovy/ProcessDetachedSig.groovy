import org.forgerock.http.protocol.*
import org.forgerock.json.jose.utils.Utils
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.secrets.jwkset.JwkSetSecretStore
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.json.jose.jwk.JWKSetParser
import org.forgerock.util.Options
import org.forgerock.util.time.Duration
import java.net.URL
import java.util.concurrent.TimeUnit
import java.util.concurrent.Future

// On the way in, build a JWT from the header and content to pass to the JWT verification filter

logger.debug("Building JWT from detached header")
def header = request.headers.get(headerName)

if (header == null) {
    logger.error("No detached signature header on inbound request " + headerName)
    def response = new Response(Status.BAD_REQUEST)
    return response
}

def detachedSig = header.firstValue.toString()

logger.debug("Inbound detached sig " + detachedSig)
def sigElements = detachedSig.split("\\.")

if (sigElements.length != 3) {
    logger.error("Wrong number of dots on inbound detached signature " +  sigElements.length)
    def response = new Response(Status.BAD_REQUEST)
    return response
}

def jwtHeader      = sigElements[0]
def jwtSignature   = sigElements[2]
def jwtPayload     = request.entity.bytes.encodeBase64Url().toString()

def jwt = jwtHeader + "." + jwtPayload + "." + jwtSignature

logger.debug("Constructed JWT " + jwt)

attributes.detachedJWT = jwt

next.handle(context,request)






