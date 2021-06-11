import java.text.SimpleDateFormat
import java.util.UUID

/*
 * Script to prepare account access consent
 * Input: OB account access intent JSON
 * Output: IDM create object
 */

def oauth2ClientId = contexts.oauth2.accessToken.info.client_id

accountIntentData = request.entity.getJson()

def tz = TimeZone.getTimeZone("UTC");
def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
df.setTimeZone(tz);
def nowAsISO = df.format(new Date());

def consentId = routeArgConsentIdPrefix + UUID.randomUUID().toString()

accountIntentData._id = consentId
accountIntentData.Data.ConsentId = consentId
accountIntentData.Data.Status = "AwaitingAuthorisation";
accountIntentData.Data.CreationDateTime = nowAsISO
accountIntentData.Data.StatusUpdateDateTime = nowAsISO
accountIntentData.apiClient = [ "_ref" : "managed/" + routeArgObjApiClient + "/" +  oauth2ClientId ]

logger.debug("final json [" + accountIntentData + "]")
request.setEntity(accountIntentData)


request.uri.path = "/openidm/managed/" + routeArgObjAccountAccessConsent
request.uri.query = "action=create";

next.handle(context, request)






