import org.forgerock.http.protocol.*
import java.text.SimpleDateFormat
import java.util.UUID

/*
 * Script to prepare account access consent
 * Input: OB account access intent JSON
 * Output: IDM create object
 */

SCRIPT_NAME = "[ProcessAccountConsent] - "
logger.debug(SCRIPT_NAME + "Running...")

def oauth2ClientId = contexts.oauth2.accessToken.info.client_id
if (oauth2ClientId == null || oauth2ClientId == "") {
    // in case of client credentials grant
    oauth2ClientId = contexts.oauth2.accessToken.info.sub
}
def method = request.method

switch(method.toUpperCase()) {

    case "POST":
        def consentId = routeArgConsentIdPrefix + UUID.randomUUID().toString()
        accountIntentData = request.entity.getJson()
        processAccountAccessRequestData(consentId, accountIntentData)

        // NOTE: creating the intent will eventually move to RS, where OBVersion and OBIntentObjectType can be determined more easily
        def version = getObApiVersion(request)
        def idmIntent = [
                _id: consentId,
                OBVersion: version,
                OBIntentObjectType: "OBReadConsentResponse1",
                OBIntentObject: accountIntentData,
                apiClient: [ "_ref" : "managed/" + routeArgObjApiClient + "/" +  oauth2ClientId ],
        ]

        logger.debug(SCRIPT_NAME + "IDM object json [" + idmIntent + "]")
        request.setEntity(idmIntent)
        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent
        request.uri.query = "action=create";
        break

    case "DELETE":
        def consentId = request.uri.path.substring(request.uri.path.lastIndexOf("/") + 1);
        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent + "/" + consentId
        return next.handle(context, request).then(response -> {
            if (response.status.isSuccessful()) {
                // OB spec expects HTTP 204 No Content response
                return new Response(Status.NO_CONTENT)
            }
            return response
        })

    case "GET":
        def consentId = request.uri.path.substring(request.uri.path.lastIndexOf("/") + 1);
        // Query IDM for a consent with the matching id, only return the OBIntentObject field
        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent + "/" + consentId
        request.uri.query = "_fields=OBIntentObject"
        break

    default:
        logger.debug(SCRIPT_NAME + "Method not supported: " + method)
        return new Response(Status.METHOD_NOT_ALLOWED);
}
return next.handle(context, request).then(this.&extractOBIntentObjectFromIdmResponse)

/**
 * Responses from IDM will always contain the "OBIntentObject" as a top level field (even if we filter).
 * We want to send only the contents of the OBIntentObject as the response to the client i.e. a valid Open Banking API response
 */
private Response extractOBIntentObjectFromIdmResponse(response) {
    if (response.status.isSuccessful()) {
        response.entity = response.entity.getJson().get("OBIntentObject")
    }
    return response
}

private void processAccountAccessRequestData(consentId, accountIntentData) {
    def tz = TimeZone.getTimeZone("UTC");
    def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    df.setTimeZone(tz);
    def nowAsISO = df.format(new Date())
    accountIntentData.Data.ConsentId = consentId
    accountIntentData.Data.Status = "AwaitingAuthorisation";
    accountIntentData.Data.CreationDateTime = nowAsISO
    accountIntentData.Data.StatusUpdateDateTime = nowAsISO
}

/**
 * Extract the Open Banking Api version from the request uri
 * Example uri: /rs/open-banking/v3.1.10/aisp/account-access-consents
 */
private String getObApiVersion(request) {
    def uri = request.uri.toString()
    def pathPrefix = "/rs/open-banking/"
    int prefixEndIndex = uri.indexOf(pathPrefix)
    if (prefixEndIndex < 0) {
        throw new IllegalStateException("Failed to determine OB API version from uri: " + uri)
    }
    int versionStartIndex = prefixEndIndex + pathPrefix.length()
    int versionEndIndex = uri.indexOf('/', versionStartIndex)
    if (versionEndIndex < 0) {
        throw new IllegalStateException("Failed to determine OB API version from uri: " + uri)
    }
    return uri.substring(versionStartIndex, versionEndIndex)
}
