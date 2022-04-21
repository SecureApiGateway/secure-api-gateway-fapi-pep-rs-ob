next.handle(context, request).thenOnResult(response -> {

  def rspJson = response.entity.getJson();


  rspJson.registration_endpoint = rspJson.registration_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
  rspJson.token_endpoint = rspJson.token_endpoint.replace(routeArgInternalUri,routeArgExternalUri)
  rspJson.issuer = rspJson.issuer.replace(routeArgInternalUri,routeArgExternalUri)

  response.setEntity(rspJson)

  return response;
})
