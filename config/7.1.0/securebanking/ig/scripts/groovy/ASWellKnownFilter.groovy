def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ASWellKnownFilter] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request).thenOnResult(response -> {
    if (response.status.isSuccessful()) {
        wellKnownData = response.entity.getJson()
        // Configure auth methods supported using filter arg: tokenEndpointAuthMethodsSupported
        wellKnownData["token_endpoint_auth_methods_supported"] = tokenEndpointAuthMethodsSupported
        response.entity.setJson(wellKnownData)
    }
})
