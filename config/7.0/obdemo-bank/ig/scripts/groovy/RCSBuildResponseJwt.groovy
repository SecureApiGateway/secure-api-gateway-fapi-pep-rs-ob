import groovy.json.JsonOutput

/*
 * Populate attribute values with claims to use in consent response JWT before signing
 */

logger.debug("request jwt is " + request.entity.getJson().consent_request.toString())
logger.debug("validated jwt is " + contexts.jwtValidation.value)
logger.debug("clientId is " + contexts.jwtValidation.claims.clientId)


attributes.requestClientId = contexts.jwtValidation.claims.clientId
attributes.requestCsrf = contexts.jwtValidation.claims.csrf
attributes.requestClaims = contexts.jwtValidation.claims.claims

attributes.requestClientName = contexts.jwtValidation.claims.client_name
attributes.requestConsentApprovalRedirectUri = contexts.jwtValidation.claims.consentApprovalRedirectUri.toString().replaceAll('"','')
attributes.requestUsername = contexts.jwtValidation.claims.username

def scopeList = []

contexts.jwtValidation.claims.scopes.asMap().each{ key, value ->
    scopeList.add(value.toString())
}

attributes.requestScopes = scopeList

attributes.responseIat = new Date().getTime() / 1000
attributes.responseExp = attributes.responseIat + (responseValidity)


next.handle(context, request)