/*
 * Copyright © 2020-2026 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import static org.forgerock.json.resource.Requests.newCreateRequest;
import static org.forgerock.json.resource.ResourcePath.resourcePath;
import static com.forgerock.sapi.gateway.rest.HttpHeaderNames.X_FAPI_INTERACTION_ID

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
    // NO_CONTENT is typically returned by deletes, these are currently not supported as the consentIdLocator will fail
    if (response.status == Status.NO_CONTENT) {
        logger.info(SCRIPT_NAME + "No Content response, skipping audit")
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
    def values = request.headers.get(X_FAPI_INTERACTION_ID)
    if (values) {
        fapiInfo.put(X_FAPI_INTERACTION_ID, values.firstValue)
    }

    auditEvent = auditEvent.add('fapiInfo', fapiInfo);

    // Send the event
    auditService.handleCreate(context, auditEventRequest("ObConsentTopic", auditEvent))
                .thenOnResultOrException(ignored -> {
                    logger.debug(SCRIPT_NAME + "Audited event for consentId: {}", consentId)
                }, e -> {
                    logger.warn("An error occurred while sending the audit event [{}]", auditEvent, e)
                })
})
