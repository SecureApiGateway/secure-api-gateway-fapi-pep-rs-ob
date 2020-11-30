import java.text.SimpleDateFormat

/*
 * Script to prepare payment consent
 * Input: OB payment intent JSON
 * Output: IDM create object
 */

// TODO: figure out why we can't pass the tpp id in as an arg from the route

def tppId = contexts.oauth2.accessToken.info.client_id


paymentIntentData = request.entity.getJson()

def tz = TimeZone.getTimeZone("UTC");
def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
df.setTimeZone(tz);
def nowAsISO = df.format(new Date());

paymentIntentData.Data.Status = "AwaitingAuthorisation";
paymentIntentData.Data.CreationDateTime = nowAsISO
paymentIntentData.Data.StatusUpdateDateTime = nowAsISO
paymentIntentData.Tpp = [ "_ref" : "managed/" + objTpp + "/" + tppId ]

logger.debug("final json [" + paymentIntentData + "]")
request.setEntity(paymentIntentData)


request.uri.path = "/openidm/managed/" + objPaymentConsent
request.uri.query = "action=create";

next.handle(context, request)






