next.handle(context, request).thenOnResult(response -> {

  def rspJson = response.entity.getJson();

  rspJson.issuer                 = rspJson.issuer.replace(routeArgInternalUri,routeArgExternalUri)
  rspJson.token_endpoint         = rspJson.token_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
  rspJson.jwks_uri               = rspJson.jwks_uri.replace(routeArgInternalUri,routeArgExternalUri)
  rspJson.registration_endpoint  = rspJson.registration_endpoint.replace(routeArgInternalUri,routeArgExternalUri)

//  rspJson.authorization_endpoint = rspJson.authorization_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
//  rspJson.introspection_endpoint = rspJson.introspection_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
//  rspJson.check_session_iframe   = rspJson.check_session_iframe.replace(routeArgInternalUri,routeArgExternalUri)
//  rspJson.end_session_endpoint   = rspJson.end_session_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
//  rspJson.revocation_endpoint    = rspJson.revocation_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
//  rspJson.userinfo_endpoint      = rspJson.userinfo_endpoint.replace(routeArgInternalUri,routeArgExternalUri)

  response.setEntity(rspJson)

  return response;
})
