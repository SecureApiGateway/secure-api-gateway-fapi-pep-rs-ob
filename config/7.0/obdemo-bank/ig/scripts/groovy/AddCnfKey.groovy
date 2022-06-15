import java.util.Base64

SCRIPT_NAME = "[AddCnfKey] - "
logger.debug(SCRIPT_NAME + "Running...")
def cnfKey = "{ \"x5t#S256\" : \"" + attributes._ig_client_certificate_thumbprint__ + "\" }"

def cnfKeyb64 = Base64.getEncoder().encodeToString(cnfKey.getBytes())

logger.debug(SCRIPT_NAME + "cnfKeyb64: " + cnfKeyb64)

request.setEntity(request.entity.getString() + '&cnf_key=' + cnfKeyb64)

next.handle(context, request)
