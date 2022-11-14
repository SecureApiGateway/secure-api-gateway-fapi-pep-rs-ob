import java.util.Base64


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[AddCnfKey] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")
def cnfKey = "{ \"x5t#S256\" : \"" + attributes._ig_client_certificate_thumbprint__ + "\" }"

def cnfKeyb64 = Base64.getEncoder().encodeToString(cnfKey.getBytes())

logger.debug(SCRIPT_NAME + "cnfKeyb64: " + cnfKeyb64)

request.setEntity(request.entity.getString() + '&cnf_key=' + cnfKeyb64)

next.handle(context, request)
