import java.text.SimpleDateFormat

/*
 * Script to prepare account access consent
 * Input: OB account access intent JSON
 * Output: IDM create object
 */

// TODO: figure out why we can't pass the tpp id in as an arg from the route

def tppId = contexts.oauth2.accessToken.info.client_id



accountIntentData = request.entity.getJson()

def tz = TimeZone.getTimeZone("UTC");
def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
df.setTimeZone(tz);
def nowAsISO = df.format(new Date());

accountIntentData.Data.Status = "AwaitingAuthorisation";
accountIntentData.Data.CreationDateTime = nowAsISO
accountIntentData.Data.StatusUpdateDateTime = nowAsISO
accountIntentData.Tpp = [ "_ref" : "managed/" + objTpp + "/" + tppId ]

logger.debug("final json [" + accountIntentData + "]")
request.setEntity(accountIntentData)


request.uri.path = "/openidm/managed/" + objAccountConsent
request.uri.query = "action=create";

next.handle(context, request)






