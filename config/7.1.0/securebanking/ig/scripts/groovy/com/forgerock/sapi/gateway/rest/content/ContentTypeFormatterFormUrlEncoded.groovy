package com.forgerock.sapi.gateway.rest.content

import org.slf4j.Logger
import org.slf4j.LoggerFactory

class ContentTypeFormatterFormUrlEncoded implements ContentTypeFormatter {

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final String logPrefix

    public ContentTypeFormatterFormUrlEncoded(String logPrefix) {
        this.logPrefix = logPrefix
    }

    String getFormattedResponse(Form errorForm) {
        logger.debug("{}getFormUrlEncodedErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        String formUrlEncodedErrorMessage = errorForm.toQueryString()
        logger.debug("{}form URL encoded error message is {}", logPrefix, formUrlEncodedErrorMessage)
        return formUrlEncodedErrorMessage
    }
}