// e.g. https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks ->
//        https://obdemo.nightly.forgerock.financial/jwkms/jwksproxy/keystore.openbankingtest.org.uk/keystore/openbanking.jwks

import groovy.json.JsonSlurper;

SCRIPT_NAME = "[JWKSProxyProcessRequest] - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponse(httpCode, message) {
  logger.error(SCRIPT_NAME + "Returning error " + httpCode + ": " + message);
  def response = new Response(httpCode);
  response.headers['Content-Type'] = "application/json";
  response.entity = "{ \"error\":\"" + message + "\"}";
  return response;
}

def splitPath = request.uri.path.split("/");

if (splitPath.length < 4) {
  return(errorResponse(Status.BAD_REQUEST,"Badly formatted proxy URL"));
}

def targetHost = splitPath[3];

if (!routeArgObJwksHosts) {
  return(errorResponse(Status.INTERNAL_SERVER_ERROR,"No authorised jwks hosts configured"));
}

def slurper = new JsonSlurper()
def authorisedHosts = slurper.parseText(routeArgObJwksHosts);

if (!authorisedHosts) {
  return(errorResponse(Status.INTERNAL_SERVER_ERROR,"Could not parse authorised jwks hosts"));
}

if (!authorisedHosts.asList().contains(targetHost)) {
  return(errorResponse(Status.FORBIDDEN,"Host " + targetHost + " not permitted"));
}

def newPath = "https://" + Arrays.copyOfRange(splitPath, 3, splitPath.length).join("/");

logger.debug(SCRIPT_NAME + "Setting path to {}", newPath);

request.setUri(newPath);

next.handle(context, request);