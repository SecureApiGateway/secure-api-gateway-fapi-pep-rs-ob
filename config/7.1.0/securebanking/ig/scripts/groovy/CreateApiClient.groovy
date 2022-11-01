import org.forgerock.http.protocol.*
import groovy.json.JsonOutput
import org.forgerock.json.jose.*
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Script to read OIDC dynamic registration response and create apiClientOrg managed object in IDM
 * with accompanying SSA managed object
 */
// TODO: review to create first the apiClientOrg and then create the apiClient, or patch the apiClientOrg when exist
// TODO: check if SSA and apiClientOrg exist before attempting create
// TODO: handle IDM error response - pass back to caller?
// TODO: handle AM bad response - reformat to OB

SCRIPT_NAME = "[CreateApiClient] - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponse(httpCode, message) {
  logger.error(SCRIPT_NAME + "Returning error " + httpCode + ": " + message);
  def response = new Response(httpCode);
  response.headers['Content-Type'] = "application/json";
  response.entity = "{ \"error\":\"" + message + "\"}";
  return response;
}

def method = request.method

switch(method.toUpperCase()) {

  case "POST":
    next.handle(context, request).thenOnResult(response -> {
      def error = false

      def clientData = response.entity.getJson();

      if (!clientData) {
        return (errorResponse(Status.BAD_REQUEST, "No registration data in response"));
      }

      def oauth2ClientId = clientData.client_id;

      def ssaJwt = attributes.registrationJWTs.ssaJwt;
      if (!ssaJwt) {
        return (errorResponse(Status.UNAUTHORIZED, "No SSA JWT"));
      }

      def ssaClaims = ssaJwt.getClaimsSet();
      def organizationName = ssaClaims.getClaim("org_name", String.class);
      def organizationIdentifier = ssaClaims.getClaim("org_id", String.class);

      def ssaSoftwareId = ssaClaims.getClaim("software_client_id")
      def ssaSoftwareName = ssaClaims.getClaim("software_client_name")
      def ssaSoftwareDescription = ssaClaims.getClaim("software_client_description")
      def clientJwksUri = attributes.registrationJWTs.registrationJwksUri;
      def clientJwks = attributes.registrationJWTs.registrationJwks;
      def ssaLogoUri = ssaClaims.getClaim("software_logo_uri", String.class)

      // response object
      response = new Response(Status.OK)
      response.headers['Content-Type'] = "application/json"
      responseMessage = "OK"

      // Create the apiClient object
      def apiClientConfig = [
              "_id"           : oauth2ClientId,
              "id"            : ssaSoftwareId,
              "name"          : ssaSoftwareName,
              "description"   : ssaSoftwareDescription,
              "ssa"           : attributes.registrationJWTs.ssaStr,
              "logoUri"       : ssaLogoUri,
              "oauth2ClientId": oauth2ClientId,
              "apiClientOrg"  : [ "_ref" : "managed/" + routeArgObjApiClientOrg + "/" +  organizationIdentifier ]
      ]

      if (clientJwksUri) {
        apiClientConfig.jwksUri = clientJwksUri;
      }

      if (clientJwks) {
        apiClientConfig.jwks = JsonOutput.toJson(clientJwks);
      }

      Request apiClientRequest = new Request();
      apiClientRequest.setMethod('POST');
      apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "?_action=create")
      apiClientRequest.getHeaders().add("Content-Type", "application/json");
      apiClientRequest.setEntity(JsonOutput.toJson(apiClientConfig));

      logger.debug(SCRIPT_NAME + "Sending apiClient create request to IDM endpoint");
      http.send(apiClientRequest).then(apiClientResponse -> {
        apiClientRequest.close()
        logger.debug(SCRIPT_NAME + "Back from IDM")

        def apiClientResponseContent = apiClientResponse.getEntity();
        def apiClientResponseStatus = apiClientResponse.getStatus();

        logger.debug(SCRIPT_NAME + "status " + apiClientResponseStatus);
        logger.debug(SCRIPT_NAME + "entity " + apiClientResponseContent);

        if (apiClientResponseStatus != Status.CREATED) {
          responseMessage = "Failed to register apiClient with IDM"
          logger.error(SCRIPT_NAME + responseMessage);
          error = true;
        } else {
          // TODO: Check if apiClientOrg already exists - if so, just add the apiClient to it

          def apiClientObj = apiClientResponse.entity.getJson();

          def apiClientId = apiClientObj._id

          // Create Institution object, and bind apiClient to it

          logger.debug(SCRIPT_NAME + "Sending apiClientOrg request to IDM endpoint");

          // We are going to include SSA data in the apiClientOrg object - working assumption
          // that there is actually only one SSA per apiClientOrg ID

          def apiClientOrgConfig = [
                  "_id"       : organizationIdentifier,
                  "id"        : organizationIdentifier,
                  "name"      : organizationName,
                  "apiClients": [["_ref": "managed/" + routeArgObjApiClient + "/" + apiClientId]]
          ]

          Request apiClientOrgRequest = new Request();

          apiClientOrgRequest.setMethod('POST');
          apiClientOrgRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClientOrg + "?_action=create");
          apiClientOrgRequest.getHeaders().add("Content-Type", "application/json");
          apiClientOrgRequest.setEntity(JsonOutput.toJson(apiClientOrgConfig));

          http.send(apiClientOrgRequest).then(apiClientOrgResponse -> {
            apiClientOrgRequest.close();
            logger.debug(SCRIPT_NAME + "Back from IDM");
            def apiClientOrgResponseContent = apiClientOrgResponse.getEntity();
            def apiClientOrgResponseStatus = apiClientOrgResponse.getStatus();

            logger.debug(SCRIPT_NAME + "status " + apiClientOrgResponseStatus);
            logger.debug(SCRIPT_NAME + "entity " + apiClientOrgResponseContent);

            if (apiClientOrgResponseStatus != Status.CREATED) {
              responseMessage = "Failed to register apiClientOrg with IDM"
              logger.error(SCRIPT_NAME + responseMessage);
              error = true;
            }
          })
        }
      })

      if (error) {
        logger.error(SCRIPT_NAME + responseMessage)
        response.status = Status.INTERNAL_SERVER_ERROR
        response.entity = "{ \"error\":\"" + responseMessage + "\"}"
        return response
      }

      return response

    });
    break
  case "DELETE":
    return next.handle(context, request).thenAsync(response -> {
      // Delete IDM object only if AM delete was successful
      if (response.status.isSuccessful()) {
        // ProcessRegistration filter will have added the client_id param
        def apiClientId = request.getQueryParams().getFirst("client_id")
        Request deleteApiClientReq = new Request()
        deleteApiClientReq.setMethod('DELETE')
        deleteApiClientReq.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
        logger.info("Deleting IDM object: " + routeArgObjApiClient + " for client_id: " + apiClientId)
        return http.send(deleteApiClientReq).thenAsync(idmResponse -> {
          if (idmResponse.status.isSuccessful()) {
            logger.debug("IDM object successfully deleted for client_id: " + apiClientId)
            return newResultPromise(new Response(Status.NO_CONTENT))
          }
          return newResultPromise(errorResponse(Status.BAD_REQUEST, "Failed to delete registration"))
        })
      }
      // AM returned an error, pass this on
      return newResultPromise(response)
    })
  case "GET":
    // Fetch the apiClient from IDM and add it as an attribute for use by other filters
    return next.handle(context, request).thenAsync(amResponse -> {
      if (amResponse.status.isSuccessful()) {
        def apiClientId = request.getQueryParams().getFirst("client_id")
        Request getApiClient = new Request()
        getApiClient.setMethod('GET')
        getApiClient.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
        logger.info("Retrieving IDM object: " + routeArgObjApiClient + " for client_id: " + apiClientId)
        return http.send(getApiClient).thenAsync(idmResponse -> {
          if (idmResponse.status.isSuccessful()) {
            var apiClient = idmResponse.getEntity().getJson()
            attributes.apiClient = apiClient
          }
          // Pass the original AM response on, the IDM response is only used to enrich the AM response (on a best effort basis)
          return newResultPromise(amResponse)
        })
      }
      // AM returned an error, pass this on
      return newResultPromise(amResponse)
    })
  default:
    logger.debug(SCRIPT_NAME + "Method not supported")
    next.handle(context, request)
}
