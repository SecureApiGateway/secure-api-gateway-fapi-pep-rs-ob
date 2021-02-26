import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

/*
 * Script to verify the TPP registration request, and prepare AM OIDC dynamic client reg
 * Input: TPP registration JWT
 * Output: Verified OIDC registration JSON
 */


def error = false

def SCOPE_ACCOUNTS = "accounts"
def SCOPE_PAYMENTS = "payments"


def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
    logger.error("No client certificate for TPP registration")
    return new Response(Status.BAD_REQUEST)
}

if (!attributes.clientCertificate.roles) {
    logger.error("No roles in client certificate for TPP registration")
    return new Response(Status.BAD_REQUEST)
}

// Parse incoming registration JWT

logger.debug("Parsing TPP request");

def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

// TODO: Check signature

// Pull the SSA from the reg data

def oidcRegistration = regJwt.getClaimsSet();

def ssa = oidcRegistration.getClaim("software_statement", String.class);

if (!ssa) {
    logger.error("No SSA")
    return new Response(Status.BAD_REQUEST)
}

logger.debug("Got ssa [" + ssa + "]")

def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)

// Going to delegate ssa signature verification to AM

def ssaClaims = ssaJwt.getClaimsSet();
def tppName = ssaClaims.getClaim("software_client_name", String.class);
def tppCertId = ssaClaims.getClaim("org_id", String.class);
def tppJwksUri = ssaClaims.getClaim("software_jwks_endpoint");

logger.debug("Inbound TPP details from SSA: tppName: {} tppCertId: {} tppJwksUri: {}",
        tppName,
        tppCertId,
        tppJwksUri
)

// Update OIDC registration request

oidcRegistration.setClaim("jwks_uri",tppJwksUri)
oidcRegistration.setClaim("client_name",tppName)
oidcRegistration.setClaim("tls_client_certificate_bound_access_tokens", true)

// Sanity check on scopes

def scopes = oidcRegistration.getClaim("scope")
def roles = attributes.clientCertificate.roles

if (scopes.contains(SCOPE_ACCOUNTS) && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
    logger.error("Requested scope {} requires certificate role {}",
            SCOPE_ACCOUNTS,
            ROLE_ACCOUNT_INFORMATION
    )
    return new Response(Status.FORBIDDEN)
}

if (scopes.contains(SCOPE_PAYMENTS) && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
    logger.error("Requested scope {} requires certificate role {}",
            SCOPE_PAYMENTS,
            ROLE_PAYMENT_INITIATION
    )
    return new Response(Status.FORBIDDEN)
}

// Cross check TPP ID with cert
//
// e.g. PSDGB-FFA-5f563e89742b2800145c7da1

def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

if (!organizationalIdentifier) {
    logger.error("No organizational identifier in cert")
    return new Response(Status.FORBIDDEN)
}

def oiComponents = organizationalIdentifier.split("-")

if (oiComponents.length != 3) {
    logger.error("Wrong number of dashes in OI {} - expected 2",organizationalIdentifier)
    return new Response(Status.FORBIDDEN)
}

def dnId = oiComponents[2]

if (dnId != tppCertId) {
    logger.error("TPP ID in cert {} does not match id in SSA {}",dnId,tppCertId)
    return new Response(Status.FORBIDDEN)
}

// TODO: Subject DN for cert bound access tokens


// Convert to JSON and pass it on

def regJson = oidcRegistration.build();

logger.debug("final json [" + regJson + "]")
request.setEntity(regJson)

next.handle(context, request)






