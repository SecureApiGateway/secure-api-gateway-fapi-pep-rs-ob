SCRIPT_NAME = "[SetContentTypeToPlainText] - "
logger.debug(SCRIPT_NAME + "Running...")

def response = new Response(Status.OK);
response.setEntity(contexts.jwtBuilder.value);
response.getHeaders().add("Content-Type","text/plain");

return response