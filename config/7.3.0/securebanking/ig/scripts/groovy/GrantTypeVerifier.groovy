import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.HttpHeaderNames

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID);
if (fapiInteractionId == null) { fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'}
SCRIPT_NAME = '[GrantTypeVerifier] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

String tokenGrantType = contexts.oauth2.accessToken.info.grant_type
logger.debug(SCRIPT_NAME + 'Access token info: ' + contexts.oauth2.accessToken.info)
logger.debug(SCRIPT_NAME + 'Token grant type: ' + tokenGrantType)

if (allowedGrantType.contains(tokenGrantType) 
    || (allowedGrantType == 'authorization_code' && tokenGrantType == 'refresh_token')) {
    next.handle(context, request)
} else {
    Response response = new Response(Status.UNAUTHORIZED)
    String message = 'invalid_grant_type'
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = 'application/json'
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}
