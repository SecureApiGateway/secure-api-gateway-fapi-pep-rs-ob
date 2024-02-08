/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.fapi;

import java.util.Optional;

import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.TransactionIdContext;

public class FAPIUtils {

    public static final String X_FAPI_INTERACTION_ID = "x-fapi-interaction-id";

    /**
     * Retrieves the x-fapi-interaction-id value from the {@link org.forgerock.services.context.AttributesContext}
     *
     * @param context Context object to extract the id from
     * @return Optional containing the x-fapi-interaction-id String or is empty.
     */
    public static Optional<String> getFapiInteractionId(Context context) {
        if (context != null && context.containsContext(AttributesContext.class)) {
            final AttributesContext attributesContext = context.asContext(AttributesContext.class);
            final Object interactionId = attributesContext.getAttributes().get(X_FAPI_INTERACTION_ID);
            if (interactionId instanceof String) {
                return Optional.of((String) interactionId);
            }
        }
        return Optional.empty();
    }

    /**
     * Function which returns the x-fapi-interaction-id from the Context or returns a string to display should one
     * not be found. This function assumes that the x-fapi-interaction-id has been set as the TransactionIdContext.
     *
     * This function is intended to be called when we wish to display the x-fapi-interaction-id for a human to read,
     * for example in a log message.
     *
     * @param context Context to extract the value from
     * @return String the x-fapi-interaction-id or "No x-fapi-interaction-id"
     * @deprecated The intended use of this methods is for when we wish to log the  x-fapi-interaction-id,
     * the value is now set in the {@link org.slf4j.MDC} and is automatically added to all logs.
     */
    @Deprecated
    public static String getFapiInteractionIdForDisplay(Context context) {
        if (context != null && context.containsContext(TransactionIdContext.class)) {
            return context.asContext(TransactionIdContext.class).getTransactionId().getValue();
        }
        return "No x-fapi-interaction-id";
    }
}
