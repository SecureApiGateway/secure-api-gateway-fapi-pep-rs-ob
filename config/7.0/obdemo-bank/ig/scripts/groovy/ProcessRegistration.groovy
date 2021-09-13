import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 */


def error = false

def SCOPE_ACCOUNTS = "accounts"
def SCOPE_PAYMENTS = "payments"


def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"
// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
    message = "No client certificate for registration"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

if (!attributes.clientCertificate.roles) {
    message = "No roles in client certificate for registration"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// Parse incoming registration JWT

logger.debug("Parsing registration request");

def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

// TODO: Check signature

// Pull the SSA from the reg data

def oidcRegistration = regJwt.getClaimsSet();

def ssa = oidcRegistration.getClaim("software_statement", String.class);

if (!ssa) {
    message = "No SSA"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
}

logger.debug("Got ssa [" + ssa + "]")

def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)

// Going to delegate ssa signature verification to AM

def ssaClaims = ssaJwt.getClaimsSet();
def apiClientOrgName = ssaClaims.getClaim("software_client_name", String.class);
def apiClientOrgCertId = ssaClaims.getClaim("org_id", String.class);
def apiClientOrgJwksUri = ssaClaims.getClaim("software_jwks_endpoint");
def apiClientOrgJwks = ssaClaims.getClaim("software_jwks");

logger.debug("Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {} apiClientOrgJwksUri: {} apiClientOrgJwks: {}",
        apiClientOrgName,
        apiClientOrgCertId,
        apiClientOrgJwksUri,
        apiClientOrgJwks
)

// Update OIDC registration request

if (apiClientOrgJwksUri) {
    logger.debug("Using jwks uri")
    oidcRegistration.setClaim("jwks_uri", apiClientOrgJwksUri)
}
else if (apiClientOrgJwks) {
    logger.debug("Using jwks")
    oidcRegistration.setClaim("jwks",  apiClientOrgJwks )
}
else {
    message = "No JWKS or JWKS URI in SSA"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}


oidcRegistration.setClaim("client_name",apiClientOrgName)
oidcRegistration.setClaim("tls_client_certificate_bound_access_tokens", true)

// Sanity check on scopes

def scopes = oidcRegistration.getClaim("scope")
def roles = attributes.clientCertificate.roles

if (scopes.contains(SCOPE_ACCOUNTS) && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
    message = "Requested scope " + SCOPE_ACCOUNTS + " requires certificate role " + ROLE_ACCOUNT_INFORMATION
    logger.error(message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

if (scopes.contains(SCOPE_PAYMENTS) && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
    message = "Requested scope " + SCOPE_PAYMENTS + " requires certificate role " + ROLE_PAYMENT_INITIATION
    logger.error(message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// Cross check ID with cert
//
// e.g. PSDGB-FFA-5f563e89742b2800145c7da1 or PSDGB-OB-Unknown0015800001041REAAY (issue by OB)

def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

if (!organizationalIdentifier) {
    message = "No organizational identifier in cert"
    logger.error(message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def oiComponents = organizationalIdentifier.split("-")

if (oiComponents.length > 3) {
    message = "Wrong number of dashes in OI " + organizationalIdentifier +" - expected 2"
    logger.error(message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// Issue: https://github.com/SecureBankingAccessToolkit/securebanking-openbanking-demo/issues/53
def dnId = oiComponents[2].toString().replace("Unknown","")

if (dnId != apiClientOrgCertId) {
    message = "apiClientOrg ID in cert " + dnId +" does not match id in SSA " + apiClientOrgCertId
    logger.error(message)
    response.status = Status.FORBIDDEN
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// TODO: Subject DN for cert bound access tokens


// Convert to JSON and pass it on

def regJson = oidcRegistration.build();

logger.debug("final json [" + regJson + "]")
request.setEntity(regJson)

next.handle(context, request)






