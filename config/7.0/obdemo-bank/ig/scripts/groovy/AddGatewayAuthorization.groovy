/*
 * Copy the IG bearer token to the token request so that it is accessible from the AM token
 * modification script. Longer term, AM modification script should have access to request headers.
 *
 * Until https://bugster.forgerock.org/jira/browse/OPENAM-18539 fixed,
 * we have to add the access token to the request URL rather than the form data in the request entity
 *
 */

SCRIPT_NAME = "[AddGatewayAuthorization] - "
logger.debug(SCRIPT_NAME + "Running...")

def authHeader = request.getHeaders().getFirst("Authorization");

if (authHeader == null) {
    def message = "Token request authorization not available";
    logger.error(SCRIPT_NAME + message)
    Response response = new Response(Status.INTERNAL_SERVER_ERROR);
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def splitHeader = authHeader.split(" ");

if (splitHeader.length != 2) {
    def message = "Token request authorization not available";
    logger.error(SCRIPT_NAME + message + " Header: " + authHeader);
    Response response = new Response(Status.INTERNAL_SERVER_ERROR);
    response.entity = "{ \"error\":\"" + message + "\"}";
    return response;
}

def bearerToken = splitHeader[1];

request.getUri().setQuery("gateway_authorization=" + bearerToken);

next.handle(context, request)
