import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoder
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientService
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientOrganisationService

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
 *
 * Java class: com.forgerock.sapi.gateway.dcr.models.ApiClient is used to represent an ApiClient. This filter adds
 * an instance of this class to the attributes context so that other filter in the chain can use it.
 */
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

apiClientService = new IdmApiClientService(http, routeArgIdmBaseUri + "/openidm/managed/", new IdmApiClientDecoder())

def method = request.method

switch(method.toUpperCase()) {
  // New registration in AM, creates a new ApiClient in IDM
  case "POST":
    return createOrUpdateRegistration(method)
  case "PUT":
    // PUT updates an existing registration, fetch it from IDM first to check it hasn't been deleted
    def apiClientId = request.getQueryParams().getFirst("client_id")
    return apiClientService.getApiClient(apiClientId).thenAsync(apiClient -> {
      return createOrUpdateRegistration(method)
    }, ex -> {
      logger.error("Failed to get ApiClient from IDM", ex)
      return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Failed to get ApiClient"))
    })
  case "DELETE":
    return next.handle(context, request).thenAsync(response -> {
      // Delete IDM object only if AM delete was successful
      if (response.status.isSuccessful()) {
        // ProcessRegistration filter will have added the client_id param
        def apiClientId = request.getQueryParams().getFirst("client_id")

        return apiClientService.deleteApiClient(apiClientId).then(
                apiClient -> {
                  attributes.put(com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient)
                  logger.debug("IDM object successfully marked as deleted client_id: " + apiClientId)
                  return new Response(Status.NO_CONTENT)
                },
                ex -> {
                  logger.error("Failed to delete registration", ex)
                  return errorResponse(Status.BAD_REQUEST, "Failed to delete registration")
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
        return apiClientService.getApiClient(apiClientId).then(apiClient -> {
          attributes.put(com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient)

          // Return the AM response containing the OAuth2 registration details
          return amResponse
        }, ex -> {
          logger.error("Failed to get ApiClient from IDM", ex)
          return errorResponse(Status.INTERNAL_SERVER_ERROR, "Failed to get ApiClient")
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

    return createApiClientOrganisation(softwareStatement).thenAsync(apiClientOrg -> {
      // POST creates new DCR and therefore must create apiClient in IDM
      if ("POST" == method) {
        logger.info(SCRIPT_NAME + " creating ApiClient using apiClientService")
        return apiClientService.createApiClient(oauth2ClientId, softwareStatement).thenCatch(ex -> {
          logger.error(SCRIPT_NAME + " failed to createApiClient due to exception", ex)
          return new Response(Status.INTERNAL_SERVER_ERROR)
        }).then(apiClient -> {
          attributes.put(com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient)
          // Return the original AM success response if we created the IDM objects
          return amResponse
        })
      } else {
        // Updating a DCR, update apiClient data in IDM
        return apiClientService.updateApiClient(oauth2ClientId, softwareStatement).then(updatedApiClient -> {
          attributes.put(com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.API_CLIENT_ATTR_KEY, updatedApiClient)
          // Return the original AM success response if we created the IDM objects
          return amResponse
        }, ex -> {
          logger.error(SCRIPT_NAME + " failed to updateApiClient due to exception", ex)
          return new Response(Status.INTERNAL_SERVER_ERROR)
        })
      }
    }, ex -> {
      logger.error(SCRIPT_NAME + " failed to createApiClientOrganisation due to exception", ex)
      return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR))
    })
  })
}


def createApiClientOrganisation(SoftwareStatement softwareStatement) {
  def apiClientOrgService = new IdmApiClientOrganisationService(http, routeArgIdmBaseUri + "/openidm/managed/")
  logger.debug(SCRIPT_NAME + "Attempting to create {} in IDM", routeArgObjApiClientOrg)
  return apiClientOrgService.createApiClientOrganisation(softwareStatement).thenOnResult(apiClientOrg -> {
      logger.debug(SCRIPT_NAME + "organisation: " + apiClientOrg + " created OR already exists")
  })
}
