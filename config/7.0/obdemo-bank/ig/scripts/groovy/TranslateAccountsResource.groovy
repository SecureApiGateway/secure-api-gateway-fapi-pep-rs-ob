SCRIPT_NAME = "[TranslateAccountsResource] - "
logger.debug(SCRIPT_NAME + "Running...")

String[] grantedAccounts = contexts.policyDecision.attributes.grantedAccounts

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

if (grantedAccounts == null) {
    message = "No granted accounts in policy response"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.INTERNAL_SERVER_ERROR
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String[] grantedPermissions = contexts.policyDecision.attributes.grantedPermissions
String[] userResourceOwner = contexts.policyDecision.attributes.userResourceOwner
if (grantedPermissions == null) {
    message = "No granted permissions in policy response"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.INTERNAL_SERVER_ERROR
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String permissions = String.join(",", grantedPermissions).toUpperCase()

String accounts = String.join(",", grantedAccounts);

request.headers.add(routeArgAccountIdsHeader, accounts)
request.headers.add(routeArgPermissionsHeader, permissions)

if(userResourceOwner[0] != null) {
    request.headers.add(routeArgUserResourceOwnerHeader, userResourceOwner[0])
}


next.handle(context, request)
