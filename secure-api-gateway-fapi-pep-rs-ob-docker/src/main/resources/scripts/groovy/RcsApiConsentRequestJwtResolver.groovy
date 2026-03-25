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
/**
 * Script which resolves the location of the Consent Request JWT for calls to the RCS Backend (API)
 *
 * There are currently 2 backend API calls:
 * - /details which populates the UI, in this call the POST body contains the jwt as a raw string
 * - /decision which submits the consent decision, in this call the POST body contains a json object with the jwt in the "consentJwt" field
 */

import static org.forgerock.util.promise.Promises.newPromise;

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[RcsApiConsentRequestJwtResolver] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

// Obtain the RCS consent JWT from the request
return filter(context, request, next)

/**
 * Filter implementation extract the RCS consent details or decision from the request and locate it on the
 * AttributesContext for use by downstream filters.
 * @param context the Context
 * @param request the request
 * @param next the next Handler
 * @return Promise of the downstream Response
 */
Promise<Response, NeverThrowsException> filter(final Context context,
                                               final Request request,
                                               final Handler next) {
    return extractConsentJwt(request)
            .then(consentJwt -> attributes.consentRequestJwt = consentJwt,
                  exception -> new Response(Status.BAD_REQUEST).setEntity(exception.getMessage()))
            .thenAsync(unused -> next.handle(context, request))
}

Promise<String, IOException> extractConsentJwt(Request request) {
    return newPromise(() -> {
        def requestPath = contexts.router.remainingUri
        if (requestPath.endsWith("/")) {
            requestPath = requestPath.substring(0, requestPath.length() - 1)
        }
        return requestPath
    })
            .thenAsync(requestPath -> {
                if (requestPath.endsWith("/details")) {
                    return request.entity.getStringAsync()
                } else if (requestPath.endsWith("/decision")) {
                    return request.entity
                                  .getJsonAsync()
                                  .then(requestJson -> requestJson.get("consentJwt"))
                } else {
                    return newExceptionPromise(
                            new IllegalArgumentException("Unsupported RCS backend URI: " + requestPath))
                }
            })
}
