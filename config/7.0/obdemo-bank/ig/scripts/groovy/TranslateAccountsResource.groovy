
String[] grantedAccounts = contexts.policyDecision.attributes.grantedAccounts

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

if (grantedAccounts == null) {
    message = "No granted accounts in policy response"
    logger.error(message)
    response.status = Status.INTERNAL_SERVER_ERROR
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String[] grantedPermissions = contexts.policyDecision.attributes.grantedPermissions

if (grantedPermissions == null) {
    message = "No granted permissions in policy response"
    logger.error(message)
    response.status = Status.INTERNAL_SERVER_ERROR
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String permissions = String.join(",", grantedPermissions).toUpperCase()

String accounts = String.join(",", grantedAccounts);

request.headers.add(routeArgAccountIdsHeader, accounts)
request.headers.add(routeArgPermissionsHeader, permissions)

next.handle(context, request)
