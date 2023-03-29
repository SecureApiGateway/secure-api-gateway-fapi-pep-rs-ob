import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement
import groovy.json.JsonOutput

import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Filter to manage apiClient and apiClientOrg objects in IDM.
 *
 * All functionality is triggered upon a successful response from AM. Callers are attempting to do DCR or manage an
 * existing registration, they are unaware of IDM specifics. Therefore, responses from this filter should be AM response
 * objects or suitable error responses.
 *
 * New apiClient and apiClientOrg objects are created in IDM when a new DCR has been completed. Note, the apiClientOrg
 * may already exist, in which case only the apiClient is created. In both cases, the apiClient is linked to the apiClientOrg
 *
 * Get, Put, Delete operations are also supported for existing IDM apiClient objects
 */

/**
 * HTTP 412 - Precondition Failed: The resource’s current version does not match the version provided.
 * Returned by IDM when this filter attempts to create an apiClientOrg that already exists
 * https://backstage.forgerock.com/docs/idm/7.2/crest/crest-status-codes.html
 */
HTTP_STATUS_PRECONDITION_FAILED = 412

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[CreateApiClient] (" + fapiInteractionId + ") - ";
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
  // New registration in AM, creates a new ApiClient in IDM
  case "POST":
    return createOrUpdateRegistration(method)
  case "PUT":
    // PUT updates an existing registration, fetch it from IDM first to check it hasn't been deleted
    def apiClientId = request.getQueryParams().getFirst("client_id")
    return getApiClient(apiClientId).thenAsync(idmResponse -> {
      // Failed to get IDM data (client may have been deleted)
      if (!idmResponse.status.isSuccessful()) {
        return newResultPromise(idmResponse)
      }
      return createOrUpdateRegistration(method)
    })
  case "DELETE":
    return next.handle(context, request).thenAsync(response -> {
      // Delete IDM object only if AM delete was successful
      if (response.status.isSuccessful()) {
        // ProcessRegistration filter will have added the client_id param
        def apiClientId = request.getQueryParams().getFirst("client_id")

        // Submit a patch request to set the apiClient.deleted field to true
        Request patchSetApiClientDeleted = new Request()
        patchSetApiClientDeleted.setMethod('POST')
        patchSetApiClientDeleted.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId
                + "?_action=patch")
        patchSetApiClientDeleted.setEntity([["operation": "replace",
                                             "field"    : "deleted",
                                             "value"    : true]])
        logger.info("Marking IDM object: " + routeArgObjApiClient + " as deleted for client_id: " + apiClientId)
        return http.send(patchSetApiClientDeleted).thenAsync(idmResponse -> {
          if (idmResponse.status.isSuccessful()) {
            logger.debug("IDM object successfully marked as deleted client_id: " + apiClientId)
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
        return getApiClient(apiClientId).then(idmResponse -> {
          // Failed to get IDM data
          if (!idmResponse.status.isSuccessful()) {
            return idmResponse
          }
          // Return the AM response containing the OAuth2 registration details
          return amResponse
        })
      }
      // AM returned an error, pass this on
      return newResultPromise(amResponse)
    })
  default:
    logger.debug(SCRIPT_NAME + "Method not supported")
    next.handle(context, request)
}

def createOrUpdateRegistration(method) {
  return next.handle(context, request).thenAsync(amResponse -> {
    // Do not create or update ApiClient if AM did not successfully process the registration
    if (!amResponse.status.isSuccessful()) {
      return newResultPromise(amResponse)
    }

    if (!attributes.registrationRequest) {
      logger.error(SCRIPT_NAME + "Required attribute not found. Please ensure the " +
              "RegistrationRequestEntityValidatorFilter is defined earlier in the chain to ensure required " +
              "registrationRequest attribute is present")
      return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Invalid gateway route"))
    }

    RegistrationRequest registrationRequest = attributes.registrationRequest
    SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()

    def oauth2ClientId = amResponse.entity.getJson().client_id
    if (!oauth2ClientId) {
      logger.error(SCRIPT_NAME + "Required client_id field not found in AM registration response")
      return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Failed to get client_id"))
    }

    def apiClientIdmObject = buildApiClientIdmObject(oauth2ClientId, softwareStatement)
    def apiClientOrgIdmObject = buildApiClientOrganisationIdmObject(softwareStatement)

    return createApiClientOrganisation(apiClientOrgIdmObject).thenAsync(createApiClientOrgResponse -> {
      if (!createApiClientOrgResponse.status.isSuccessful()) {
        return newResultPromise(createApiClientOrgResponse)
      }
      // POST creates new DCR and therefore must create apiClient in IDM
      if ("POST".equals(method)) {
        return createApiClient(apiClientIdmObject).then(createApiClientResponse -> {
          if (!createApiClientResponse.status.isSuccessful()) {
            return createApiClientResponse
          } else {
            // Return the original AM success response if we created the IDM objects
            return amResponse
          }
        })
      } else {
        // Updating a DCR, update apiClient data in IDM
        return updateApiClient(apiClientIdmObject).then(updateApiClientResponse -> {
          if (!updateApiClientResponse.status.isSuccessful()) {
            return updateApiClientResponse
          } else {
            // Return the original AM success response if we updated the IDM objects
            return amResponse
          }
        })
      }
    })
  })
}

def buildApiClientIdmObject(oauth2ClientId, softwareStatement) {
  def apiClientIdmObj = [
          "_id"           : oauth2ClientId,
          "id"            : softwareStatement.getSoftwareId(),
          "name"          : softwareStatement.getClientName(),
          "ssa"           : softwareStatement.getB64EncodedJwtString(),
          "roles"         : softwareStatement.getRoles(),
          "oauth2ClientId": oauth2ClientId,
          "apiClientOrg"  : ["_ref": "managed/" + routeArgObjApiClientOrg + "/" + softwareStatement.getOrgId()]
  ]

  if (softwareStatement.hasJwksUri()){
    apiClientIdmObj.jwksUri = softwareStatement.getJwksUri()
  } else {
    apiClientIdmObj.jwks = softwareStatement.getJwksSet().toJsonValue()
    logger.debug("jwks is '{}'", apiClientIdmObj)
  }

  return apiClientIdmObj
}

def buildApiClientOrganisationIdmObject(SoftwareStatement softwareStatement) {
  def organisationName = softwareStatement.getOrgId()
  def organisationIdentifier = softwareStatement.getOrgId()
  return [
          "_id" : organisationIdentifier,
          "id"  : organisationIdentifier,
          "name": organisationName,
  ]
}

def createApiClientOrganisation(apiClientOrgIdmObject) {
  Request apiClientOrgRequest = new Request()
  apiClientOrgRequest.setMethod('PUT')
  apiClientOrgRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClientOrg + "/" + apiClientOrgIdmObject["_id"])
  apiClientOrgRequest.addHeaders(new GenericHeader("If-None-Match", "*")) // Prevent updating an existing apiClientOrg
  apiClientOrgRequest.setEntity(apiClientOrgIdmObject)
  logger.debug(SCRIPT_NAME + "Attempting to create {} in IDM", routeArgObjApiClientOrg)
  return http.send(apiClientOrgRequest).then(apiClientOrgResponse -> {
    if (!apiClientOrgResponse.status.isSuccessful() && apiClientOrgResponse.status.code != HTTP_STATUS_PRECONDITION_FAILED) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to create {}, status: {}, entity: {}", routeArgObjApiClientOrg, apiClientOrgResponse.status, apiClientOrgResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      logger.debug(SCRIPT_NAME + "organisation created OR already exists")
      apiClientOrgResponse.status = Status.CREATED
      return apiClientOrgResponse
    }
  })
}

def createApiClient(apiClientIdmObject) {
  Request apiClientRequest = new Request()
  apiClientRequest.setMethod('POST')
  apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "?_action=create")
  apiClientRequest.setEntity(apiClientIdmObject)
  logger.debug(SCRIPT_NAME + "Attempting to create {} in IDM", routeArgObjApiClient)
  return http.send(apiClientRequest).then(apiClientResponse -> {
    if (apiClientResponse.status != Status.CREATED) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to create {}, status: {}, entity: {}", routeArgObjApiClient, apiClientResponse.status, apiClientResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      logger.debug(SCRIPT_NAME + "successfully created apiClient")
      return apiClientResponse
    }
  })
}

def updateApiClient(apiClientIdmObject) {
  Request apiClientRequest = new Request()
  apiClientRequest.setMethod('PUT')
  apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientIdmObject["_id"])
  apiClientRequest.setEntity(apiClientIdmObject)
  logger.debug(SCRIPT_NAME + "Attempting to update {} _id: {} in IDM", routeArgObjApiClient, apiClientIdmObject["_id"])
  return http.send(apiClientRequest).then(apiClientResponse -> {
    if (!apiClientResponse.status.isSuccessful()) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to update {}, status: {}, entity: {}", routeArgObjApiClient, apiClientResponse.status, apiClientResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      logger.debug(SCRIPT_NAME + "successfully updated apiClient")
      return apiClientResponse
    }
  })
}

def getApiClient(apiClientId) {
  Request getApiClient = new Request()
  getApiClient.setMethod('GET')
  getApiClient.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
  logger.info("Retrieving IDM object: " + routeArgObjApiClient + " for client_id: " + apiClientId)
  return http.send(getApiClient).then(apiClientResponse -> {
    if (!apiClientResponse.status.isSuccessful()) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to get {}, status: {}, entity: {}", routeArgObjApiClient, apiClientResponse.status, apiClientResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      // Handle case where ApiClient has been deleted by an admin user in IDM but the AM OAuth2 client is still active.
      var apiClient = apiClientResponse.getEntity().getJson()
      if (apiClient.deleted) {
        logger.warn("Failed to retrieve apiClient for client_id: " + apiClientId + " , client has been deleted in IDM")
        return errorResponse(Status.UNAUTHORIZED, "Failed to get registration")
      }
      // Add the apiClient to the attributes context for use by other filters
      attributes.apiClient = apiClient
      return apiClientResponse
    }
  })
}
