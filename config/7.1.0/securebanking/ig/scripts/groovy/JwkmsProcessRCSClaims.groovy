import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[JwkmsProcessRCSClaims] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Signing claims as RCS")

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def payload = request.entity.getJson();

if (!payload) {
    message = "Couldn't parse request JSON"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def iat = new Date().getTime() / 1000;

payload.put("iss",routeArgJwtIssuer)
payload.put("iat",iat)
payload.put("exp",iat + (routeArgJwtValidity))


attributes.processedPayload = payload

next.handle(context,request)






