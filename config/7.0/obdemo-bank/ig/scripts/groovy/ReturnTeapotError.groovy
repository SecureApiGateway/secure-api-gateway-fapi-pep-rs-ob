SCRIPT_NAME = "[ReturnTeapotError] - "
logger.debug(SCRIPT_NAME + "Running...")

def response = new Response(Status.TEAPOT);
response.entity = "Failure in CertificateThumbprintFilter"

return response