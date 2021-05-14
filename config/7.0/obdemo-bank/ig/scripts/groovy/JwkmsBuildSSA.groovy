import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*
import org.forgerock.json.jose.jwk.RsaJWK
import java.security.PublicKey
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jwk.KeyUseConstants

logger.debug("Creating SSA")

def requestObj = request.entity.getJson()

def iss = routeArgJwtIssuer
def iat = new Date().getTime() / 1000;
def exp = iat + routeArgJwtValidity;


// Check we have everything we need from the client certificate

if (!attributes.clientCertificate) {
    logger.error("No client certificate for registration")
    return new Response(Status.BAD_REQUEST)
}


if (!attributes.clientCertificate.subjectDNComponents.CN) {
    logger.error("No CN in cert")
    return new Response(Status.BAD_REQUEST)
}


def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

if (!organizationalIdentifier) {
    logger.error("No org identifier in cert")
    return new Response(Status.BAD_REQUEST)
}

def oiComponents = organizationalIdentifier.split("-")

if (oiComponents.length != 3) {
    logger.error("Wrong number of dashes in OI {} - expected 2",organizationalIdentifier)
    return new Response(Status.FORBIDDEN)
}

def org_id = oiComponents[2]
def org_name = attributes.clientCertificate.subjectDNComponents.CN;


PublicKey  publicKey = attributes.clientCertificate.publicKey
def algorithm = JwsAlgorithm.PS256
def kid = attributes.clientCertificate.serialNumber.toString()

RsaJWK jwk = RsaJWK.builder(publicKey)
        .algorithm(algorithm)
        .keyId(kid)
        .keyUse(KeyUseConstants.SIG)
        .build()

def jwkString = jwk.toJsonString()


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
    "software_jwks": [ "keys": [ jwk.toJsonValue().object ]]
]


logger.debug("Built SSA payload " + payload)
attributes.ssaPayload = payload

next.handle(context,request)






