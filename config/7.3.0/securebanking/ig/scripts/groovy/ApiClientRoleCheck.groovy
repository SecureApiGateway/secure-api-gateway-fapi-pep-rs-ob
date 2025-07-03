import org.forgerock.openig.fapi.apiclient.ApiClientFapiContext;

// Check transport certificate for roles appropriate to request
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ApiClientRoleCheck] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")
logger.debug(SCRIPT_NAME + "Checking certificate roles for {} request", routeArgRole)

def apiClientFapiContext = context.asContext(ApiClientFapiContext.class)
def apiClientOpt = apiClientFapiContext.getApiClient()
if (apiClientOpt.isEmpty()) {
    logger.error("apiClient must be identified before this script - it should exist in the ApiClientFapiContext")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

def apiClient = apiClientOpt.get()
if (!apiClient.getRoles().contains(routeArgRole)) {
    def errorMessage = "client is not authorized to perform role: " + routeArgRole
    logger.warn(SCRIPT_NAME + "ApiClient.id=" + apiClient.getOauth2ClientId() + " " + errorMessage)

    def response = new Response(Status.FORBIDDEN)
    response.entity = json(object(field("error", errorMessage)))
    return response
}

next.handle(context, request)
