import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*


logger.debug("Processing JWKMS request")

def payload = request.entity.getJson()

def iat = new Date().getTime() / 1000;

payload.put("iss",routeArgJwtIssuer)
payload.put("iat",iat)
payload.put("exp",iat + (routeArgJwtValidity))


attributes.processedPayload = payload

next.handle(context,request)






