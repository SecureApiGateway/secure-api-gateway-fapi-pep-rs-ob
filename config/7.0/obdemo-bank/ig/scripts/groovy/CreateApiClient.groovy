import org.forgerock.http.protocol.*
import groovy.json.JsonOutput
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

/*
 * Script to read OIDC dynamic registration response and create apiClientOrg managed object in IDM
 * with accompanying SSA managed object
 */

// TODO: check if SSA and apiClientOrg exist before attempting create
// TODO: handle IDM error response - pass back to caller?



next.handle(context, request).thenOnResult(response -> {
  def error = false

  def clientData = response.entity.getJson();

  // Pull the apiClientOrg managed object info from the OIDC client data

  def ssa = clientData.software_statement
  def oauth2ClientId = clientData.client_id;

  // Unpack the SSA within the client data

  def ssaJws = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)
  def ssaClaims = ssaJws.getClaimsSet();
  def organizationName = ssaClaims.getClaim("org_name", String.class);
  def organizationIdentifier = ssaClaims.getClaim("org_id", String.class);

  def ssaSoftwareId = ssaClaims.getClaim("software_client_id")
  def ssaSoftwareName = ssaClaims.getClaim("software_client_name")
  def ssaSoftwareDescription = ssaClaims.getClaim("software_client_description")


  def clientJwksUri = ssaClaims.getClaim("software_jwks_endpoint", String.class)
  def clientJwks = ssaClaims.getClaim("software_jwks")
  def ssaLogoUri = ssaClaims.getClaim("software_logo_uri", String.class)

  // Create the apiClient object

  logger.debug("Sending apiClient create request to IDM endpoint");

  def apiClientConfig = [
          "_id" : oauth2ClientId,
          "id" : ssaSoftwareId,
          "name" : ssaSoftwareName,
          "description": ssaSoftwareDescription,
          "ssa" : ssa,
          "jwksUri" : clientJwksUri,
          "jwks": JsonOutput.toJson(clientJwks),
          "logoUri" : ssaLogoUri,
          "oauth2ClientId": oauth2ClientId
  ]

  Request apiClientRequest = new Request();

  apiClientRequest.setMethod('POST');
  apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "?_action=create")
  apiClientRequest.getHeaders().add("Content-Type","application/json");
  apiClientRequest.setEntity(JsonOutput.toJson(apiClientConfig));

  http.send(apiClientRequest).then(apiClientResponse -> {
    apiClientRequest.close()
    logger.debug("Back from IDM")

    def apiClientResponseContent = apiClientResponse.getEntity();
    def apiClientResponseStatus = apiClientResponse.getStatus();

    logger.debug("status " + apiClientResponseStatus);
    logger.debug("entity " + apiClientResponseContent);

     if (apiClientResponseStatus != Status.CREATED) {
       logger.error("Failed to register apiClient with IDM");
       error = true;
     }
     else {
       // TODO: Check if apiClientOrg already exists - if so, just add the apiClient to it

       def apiClientObj = apiClientResponse.entity.getJson();

       def apiClientId = apiClientObj._id

       // Create Institution object, and bind apiClient to it

       logger.debug("Sending apiClientOrg request to IDM endpoint");

       // We are going to include SSA data in the apiClientOrg object - working assumption
       // that there is actually only one SSA per apiClientOrg ID

       def apiClientOrgConfig = [
               "_id": organizationIdentifier,
               "id": organizationIdentifier,
               "name": organizationName,
               "apiClients" : [[ "_ref" : "managed/" + routeArgObjApiClient + "/" + apiClientId ]]
       ]

       Request apiClientOrgRequest = new Request();

       apiClientOrgRequest.setMethod('POST');
       apiClientOrgRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClientOrg + "?_action=create");
       apiClientOrgRequest.getHeaders().add("Content-Type","application/json");
       apiClientOrgRequest.setEntity(JsonOutput.toJson(apiClientOrgConfig));

       http.send(apiClientOrgRequest).then(apiClientOrgResponse -> {
               apiClientOrgRequest.close() ;
               logger.debug("Back from IDM") ;
         def apiClientOrgResponseContent = apiClientOrgResponse.getEntity();
         def apiClientOrgResponseStatus = apiClientOrgResponse.getStatus();

         logger.debug("status " + apiClientOrgResponseStatus);
         logger.debug("entity " + apiClientOrgResponseContent);

         if (apiClientOrgResponseStatus != Status.CREATED) {
           logger.error("Failed to register apiClientOrg with IDM");
           error = true;
         }
       })
     }
  })

  if (error) {
    response = new Response(Status.INTERNAL_SERVER_ERROR)
    return response
  }

  return response

});








