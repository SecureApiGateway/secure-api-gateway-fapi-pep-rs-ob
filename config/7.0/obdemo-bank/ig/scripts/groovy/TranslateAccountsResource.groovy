
String[] grantedAccounts = contexts.policyDecision.attributes.grantedAccounts

if (grantedAccounts == null) {
    logger.error("No granted accounts in policy response")
    Response response = new Response(Status.INTERNAL_SERVER_ERROR)
    return response
}

String[] grantedPermissions = contexts.policyDecision.attributes.grantedPermissions

if (grantedPermissions == null) {
    logger.error("No granted permissions in policy response")
            Response response = new Response(Status.INTERNAL_SERVER_ERROR)
    return response
}

String permissions = String.join(",", grantedPermissions).toUpperCase()

String accounts = String.join(",", grantedAccounts);

request.headers.add(routeArgAccountIdsHeader, accounts)
request.headers.add(routeArgPermissionsHeader, permissions)

next.handle(context, request)
