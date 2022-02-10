import java.text.SimpleDateFormat

/*
 * Script to prepare payment consent
 * Input: OB payment intent JSON
 * Output: IDM create object
 */

def apiClientId = contexts.oauth2.accessToken.info.client_id


paymentIntentData = request.entity.getJson()

def tz = TimeZone.getTimeZone("UTC");
def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
df.setTimeZone(tz);
def nowAsISO = df.format(new Date());

def consentId = routeArgConsentIdPrefix + UUID.randomUUID().toString()

paymentIntentData._id = consentId
paymentIntentData.Data.ConsentId = consentId
paymentIntentData.Data.Status = "AwaitingAuthorisation";
paymentIntentData.Data.CreationDateTime = nowAsISO
paymentIntentData.Data.StatusUpdateDateTime = nowAsISO
paymentIntentData.apiClient = [ "_ref" : "managed/" + routeArgObjApiClient + "/" + apiClientId ]

logger.debug("final json [" + paymentIntentData + "]")
request.setEntity(paymentIntentData)


request.uri.path = "/openidm/managed/" + routeArgObjDomesticPaymentConsent
request.uri.query = "action=create";

next.handle(context, request)






