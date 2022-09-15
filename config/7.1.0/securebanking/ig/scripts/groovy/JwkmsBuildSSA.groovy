import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*

SCRIPT_NAME = "[JwkmsBuildSSA] - "
logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Creating SSA")

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def requestObj = request.entity.getJson()

def iss = routeArgJwtIssuer
def iat = new Date().getTime() / 1000;
def exp = iat + routeArgJwtValidity;


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
    message = "No client certificate for registration"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}


if (!attributes.clientCertificate.subjectDNComponents.CN) {
    message = "No CN in cert"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}


def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

if (!organizationalIdentifier) {
    message = "No org identifier in cert"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def oiComponents = organizationalIdentifier.split("-")

if (oiComponents.length != 3) {
    message = "Wrong number of dashes in OI " + organizationalIdentifier + " - expected 2"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def org_id = oiComponents[2]
def org_name = attributes.clientCertificate.subjectDNComponents.CN;


def payload = [
    "iss": iss,
    "iat": iat,
    "exp": exp,
    "org_id": org_id,
    "org_name": org_name,
    "org_status": "Active",
    "software_mode": "TEST",
    "software_id": requestObj.software_id,
    "software_client_name": requestObj.software_client_name,
    "software_client_id": requestObj.software_client_id,
    "software_tos_uri": requestObj.software_tos_uri,
    "software_client_description": requestObj.software_client_description,
    "software_redirect_uris": requestObj.software_redirect_uris,
    "software_policy_uri": requestObj.software_policy_uri,
    "software_logo_uri": requestObj.software_logo_uri,
    "software_roles": requestObj.software_roles,
    "software_jwks": requestObj.software_jwks
]


logger.debug(SCRIPT_NAME + "Built SSA payload " + payload)
attributes.ssaPayload = payload

next.handle(context,request)






