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
def method = request.method

switch(method.toUpperCase()) {

    case "POST":
        accountIntentData = request.entity.getJson()
        def tz = TimeZone.getTimeZone("UTC");
        def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(tz);
        def nowAsISO = df.format(new Date());

        def consentId = routeArgConsentIdPrefix + UUID.randomUUID().toString()

        accountIntentData._id = consentId
        accountIntentData.Data.ConsentId = consentId
        accountIntentData.Data.Status = "AwaitingAuthorisation";
        accountIntentData.Data.CreationDateTime = nowAsISO
        accountIntentData.Data.StatusUpdateDateTime = nowAsISO
        accountIntentData.apiClient = [ "_ref" : "managed/" + routeArgObjApiClient + "/" +  oauth2ClientId ]

        logger.debug(SCRIPT_NAME + "final json [" + accountIntentData + "]")
        request.setEntity(accountIntentData)

        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent
        request.uri.query = "action=create";
        break

    case "DELETE":
        def consentId = request.uri.path.substring(request.uri.path.lastIndexOf("/") + 1);
        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent + "/" + consentId
        break

    case "GET":
        def consentId = request.uri.path.substring(request.uri.path.lastIndexOf("/") + 1);
        request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent + "/" + consentId
        break

    default:
        logger.debug(SCRIPT_NAME + "Method not supported")

}


next.handle(context, request)






