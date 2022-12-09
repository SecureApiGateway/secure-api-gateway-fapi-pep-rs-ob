package com.forgerock.sapi.gateway.rest.content

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.forgerock.http.util.Json

class ContentTypeFormatterJson implements ContentTypeFormatter {

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final String logPrefix

    public ContentTypeFormatterJson(String logPrefix) {
        this.logPrefix = logPrefix
    }

    String getFormattedResponse(Form errorForm) {
        logger.debug("{}getJsonErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        String jsonErrorMessage = new String(Json.writeJson(errorForm))
        logger.debug("{}html error message is {}", logPrefix, jsonErrorMessage)
        return jsonErrorMessage
    }
}
