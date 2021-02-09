import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*

// On the way in, build a JWT from the header and content to pass to the JWT verification filter

logger.debug("Building JWT from detached header")
def header = request.headers.get(_arg_headerName)

if (header == null) {
    logger.error("No detached signature header on inbound request " + _arg_headerName)
    Response response = new Response(Status.BAD_REQUEST)
    return response
}

String detachedSig = header.firstValue.toString()

logger.debug("Inbound detached sig " + detachedSig)
String[] sigElements = detachedSig.split("\\.")

if (sigElements.length != 3) {
    logger.error("Wrong number of dots on inbound detached signature " +  sigElements.length)
    Response response = new Response(Status.BAD_REQUEST)
    return response
}

String jwtHeader      = sigElements[0]
String jwtSignature   = sigElements[2]
String jwtPayload     = request.entity.bytes.encodeBase64Url().toString()

String jwt = jwtHeader + "." + jwtPayload + "." + jwtSignature

logger.debug("Constructed JWT " + jwt)

attributes.detachedJWT = jwt

next.handle(context,request)






