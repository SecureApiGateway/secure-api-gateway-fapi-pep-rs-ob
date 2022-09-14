import org.forgerock.http.protocol.*

SCRIPT_NAME = "[GrantTypeVerifier] - "
logger.debug(SCRIPT_NAME + "Running...")

def tokenGrantType = contexts.oauth2.accessToken.info.grant_type
logger.debug(SCRIPT_NAME + "Access token info: " + contexts.oauth2.accessToken.info)
logger.debug(SCRIPT_NAME + "Token grant type: " + tokenGrantType)

if (tokenGrantType == allowedGrantType) {
    next.handle(context, request)
} else {
    Response response = new Response(Status.UNAUTHORIZED)
    def message = "invalid_grant_type"
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = "application/json"
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response;
}


