import static org.forgerock.json.resource.Requests.newCreateRequest;
import static org.forgerock.json.resource.ResourcePath.resourcePath;

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[AuditConsent] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")

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


  ['x-fapi-interaction-id', 'x-fapi-financial-id'].each { header ->
    def values = request.headers.get(header)
    if (values) {
        fapiInfo.put( header, values.firstValue)
    }

  }

  auditEvent = auditEvent.add('fapiInfo', fapiInfo);

  // Send the event
  auditService.handleCreate(context, auditEventRequest("ObConsentTopic", auditEvent));

  return response
})
