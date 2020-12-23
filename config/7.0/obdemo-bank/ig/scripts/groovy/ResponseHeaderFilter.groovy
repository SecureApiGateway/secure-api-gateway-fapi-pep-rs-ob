import org.forgerock.http.protocol.*

INTERACTIONID_HEADER = "x-fapi-interaction-id"

next.handle(context, request).thenOnResult(response -> {
  // Replay x-fapi-interaction-id (or create one if not present on request)
  values = request.headers.get(INTERACTIONID_HEADER)
  if (values == null) {
    id = UUID.randomUUID().toString();
    logger.debug("No inbound interaction id - created one")
  }
  else{
    id = values.firstValue;
  }
  response.headers.add(INTERACTIONID_HEADER, id)

  return response;
})










