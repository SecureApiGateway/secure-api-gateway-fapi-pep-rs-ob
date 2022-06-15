SCRIPT_NAME = "[TranslatePaymentResource] - "
logger.debug(SCRIPT_NAME + "Running...")

request.headers.add(routeArgAccountIdHeader, attributes.get("accountId"))

next.handle(context, request)
