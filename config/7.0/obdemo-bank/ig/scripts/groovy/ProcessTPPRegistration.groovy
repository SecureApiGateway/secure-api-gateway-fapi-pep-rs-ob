import org.forgerock.http.protocol.*
import org.forgerock.json.jose.utils.Utils
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

/*
 * Script to verify the TPP registration request, and prepare AM OIDC dynamic client reg
 * Input: TPP registration JWT
 * Output: Verified OIDC registration JSON
 */


def error = false

// Parse incoming registration JWT

logger.debug("Parsing TPP request");

def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

// TODO: Check signature

// Pull the SSA from the reg data

def oidcRegistration = regJwt.getClaimsSet();

def ssa = oidcRegistration.getClaim("software_statement", String.class);

logger.debug("Got ssa [" + ssa + "]")

def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)

// Going to delegate ssa signature verification to AM

def ssaClaims = ssaJwt.getClaimsSet();
def tppName = ssaClaims.getClaim("software_client_name", String.class);
def tppCertId = ssaClaims.getClaim("org_id", String.class);
def tppJwksUri = ssaClaims.getClaim("software_jwks_endpoint");


// Update OIDC registration request

oidcRegistration.setClaim("jwks_uri",tppJwksUri)
oidcRegistration.setClaim("client_name",tppName)
oidcRegistration.setClaim("tls_client_certificate_bound_access_tokens", true)

// TODO: Map scopes to roles
// TODO: Subject DN for cert bound access tokens
// TODO: Cross check software id with transport cert

// Convert to JSON and pass it on

def regJson = oidcRegistration.build();

logger.debug("final json [" + regJson + "]")
request.setEntity(regJson)

next.handle(context, request)






