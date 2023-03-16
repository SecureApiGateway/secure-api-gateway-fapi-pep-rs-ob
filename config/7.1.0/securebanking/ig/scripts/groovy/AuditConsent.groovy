import static org.forgerock.json.resource.Requests.newCreateRequest;
import static org.forgerock.json.resource.ResourcePath.resourcePath;

SCRIPT_NAME = "[AuditConsent] - "

// Helper functions
def String transactionId() {
  return contexts.transactionId.transactionId.value;
}

def JsonValue auditEvent(String eventName) {
  return json(object(field('eventName', eventName),
          field('transactionId', transactionId()),
          field('timestamp', clock.instant().toEpochMilli())));
}

def auditEventRequest(String topicName, JsonValue auditEvent) {
  return newCreateRequest(resourcePath("/" + topicName), auditEvent);
}

def resourceEvent() {
  return object(field('path', request.uri.path),
          field('method', request.method));
}


next.handle(context, request).thenOnResult(response -> {
    logger.debug(SCRIPT_NAME + "Running...")
    if (!response.status.isSuccessful()) {
        logger.info(SCRIPT_NAME + "Error response, skipping audit")
        return
    }

    logger.info(SCRIPT_NAME + context)

    def binding = new Binding()
    binding.response = response
    binding.contexts = contexts
    consentId = new GroovyShell(binding).evaluate(consentIdLocator)

    def consent = object(
          field('id', consentId),
          field('role', role)
    )
    // Build the event
    JsonValue auditEvent = auditEvent('OB-CONSENT-' + event).add('consent', consent)

    def fapiInfo = [:]
    def values = request.headers.get('x-fapi-interaction-id')
    if (values) {
        fapiInfo.put( header, values.firstValue)
    }


    auditEvent = auditEvent.add('fapiInfo', fapiInfo);

    // Send the event
    auditService.handleCreate(context, auditEventRequest("ObConsentTopic", auditEvent))
    logger.debug(SCRIPT_NAME + "audited event for consentId: " + consentId)
})
