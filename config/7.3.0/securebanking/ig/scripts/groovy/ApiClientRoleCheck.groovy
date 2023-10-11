import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*

// Check transport certificate for roles appropriate to request
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ApiClientRoleCheck] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")
logger.debug(SCRIPT_NAME + "Checking certificate roles for {} request", routeArgRole)

if (!attributes.apiClient){
  logger.error("FetchApiClientFilter must be run before this script. apiClient needs to exist in the attributes context");
  return new Response(Status.INTERNAL_SERVER_ERROR)
}

if (!attributes.apiClient.getRoles().contains(routeArgRole)) {
  def errorMessage = "client is not authorized to perform role: " + routeArgRole
  logger.warn(SCRIPT_NAME + "ApiClient.id=" + attributes.apiClient.getOauth2ClientId() + " " + errorMessage)
  
  def response = new Response(Status.FORBIDDEN)
  response.entity = json(object(field("error", errorMessage)))
  return response
}

next.handle(context, request)
