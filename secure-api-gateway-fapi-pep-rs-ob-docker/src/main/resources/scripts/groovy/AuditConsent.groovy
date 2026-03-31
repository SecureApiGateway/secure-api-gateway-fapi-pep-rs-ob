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

SCRIPT_NAME = "[AuditConsent] - "
next.handle(context, request)
    .thenOnResult(response -> {
        logger.debug(SCRIPT_NAME + "Running...")
        if (!response.status.isSuccessful()) {
            logger.info(SCRIPT_NAME + "Error response, skipping audit")
            return
        }

        // NO_CONTENT is typically returned by deletes, these are currently not supported as the consentIdLocator
        // will fail
        if (response.status == Status.NO_CONTENT) {
            logger.info(SCRIPT_NAME + "No Content response, skipping audit")
            return
        }

        def binding = new Binding()
        binding.response = response
        binding.contexts = contexts
        consentId = new GroovyShell(binding).evaluate(consentIdLocator)

        if (consentId == null) {
            logger.info(SCRIPT_NAME + "Consent ID is null, skipping audit")
            return
        }

        contexts.accessAuditExtension.extendWith('ob-consent-id', consentId)
                                     .extendWith('ob-consent-role', role);

})
