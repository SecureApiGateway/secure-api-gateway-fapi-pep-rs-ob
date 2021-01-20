import org.forgerock.http.protocol.*
import org.forgerock.json.jose.utils.Utils
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

/*
 * Script to read OIDC dynamic registration response and create TPP managed object in IDM
 * with accompanying SSA managed object
 */

// TODO: check if SSA and TPP exist before attempting create
// TODO: handle IDM error response - pass back to caller?

def error = false

next.handle(context, request).thenOnResult(response -> {

  def clientData = response.entity.getJson();

  // Pull the TPP managed object info from the OIDC client data

  def clientSsa = clientData.software_statement
  def clientIdentifier = clientData.client_id;

  // Unpack the SSA within the client data

  def ssaJws = new JwtReconstruction().reconstructJwt(clientSsa,SignedJwt.class)
  def ssaClaims = ssaJws.getClaimsSet();
  def clientName = ssaClaims.getClaim("org_name", String.class);
  def clientCertId = ssaClaims.getClaim("org_id", String.class);
  def clientJwksUri = ssaClaims.getClaim("software_jwks_endpoint", String.class)

  // Create the SSA object

  logger.debug("Sending SSA request to IDM endpoint");

  def ssaConfig = [
          "ssa" : clientSsa
  ]

  Request ssaRequest = new Request();

  ssaRequest.setMethod('POST');
  ssaRequest.setUri(idmBaseUri + "/openidm/managed/" + objSsa + "?_action=create")
  ssaRequest.getHeaders().add("Content-Type","application/json");
  ssaRequest.setEntity(JsonOutput.toJson(ssaConfig));

  http.send(ssaRequest).then(ssaResponse -> {
    ssaRequest.close()
    logger.debug("Back from IDM")

    def ssaResponseContent = ssaResponse.getEntity();
    def ssaResponseStatus = ssaResponse.getStatus();

    logger.debug("status " + ssaResponseStatus);
    logger.debug("entity " + ssaResponseContent);

     if (ssaResponseStatus != Status.CREATED) {
       logger.error("Failed to register SSA with IDM");
       error = true;
     }
     else {

       def ssaObj = ssaResponse.entity.getJson();

       def ssaId = ssaObj._id

       // Create TPP object, and bind SSA to it

       logger.debug("Sending TPP request to IDM endpoint");

       def tppConfig = [
               "_id": clientIdentifier,
               "name": clientName,
               "identifier": clientIdentifier,
               "certId": clientCertId,
               "jwksUri" : clientJwksUri,
               "ssa": clientSsa,
               "ssas" : [[ "_ref" : "managed/" + objSsa + "/" + ssaId ]]
       ]

       Request tppRequest = new Request();

       tppRequest.setMethod('POST');
       tppRequest.setUri(idmBaseUri + "/openidm/managed/" + objTpp + "?_action=create");
       tppRequest.getHeaders().add("Content-Type","application/json");
       tppRequest.setEntity(JsonOutput.toJson(tppConfig));

       http.send(tppRequest).then(tppResponse -> {
               tppRequest.close() ;
               logger.debug("Back from IDM") ;
         def tppResponseContent = tppResponse.getEntity();
         def tppResponseStatus = tppResponse.getStatus();

         logger.debug("status " + tppResponseStatus);
         logger.debug("entity " + tppResponseContent);

         if (tppResponseStatus != Status.CREATED) {
           logger.error("Failed to register TPP with IDM");
           error = true;
         }
       })
     }
  })

  return response;

});








