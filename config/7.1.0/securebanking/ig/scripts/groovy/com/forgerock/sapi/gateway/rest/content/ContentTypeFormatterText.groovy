package com.forgerock.sapi.gateway.rest.content

import org.slf4j.Logger
import org.slf4j.LoggerFactory

class ContentTypeFormatterText implements ContentTypeFormatter {

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final String logPrefix

    ContentTypeFormatterText(String logPrefix) {
        this.logPrefix = logPrefix
    }

    String getFormattedResponse(Form errorForm) {
        logger.debug("{}getTextErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        StringBuilder errorMessageBuilder = new StringBuilder()
        errorForm.forEach((key, val) -> {
            logger.debug("{}processing entry for {}, val is {}", logPrefix, key, val)
            errorMessageBuilder.append(key + ": ")
            List<String> values = val
            Boolean first = true
            values.forEach((innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if (!first) {
                    errorMessageBuilder.append(', ')
                }
                errorMessageBuilder.append(innerVal)
                first = false
            })
            errorMessageBuilder.append('\n')
        })
        String textErrorMessage = errorMessageBuilder.toString()
        logger.debug("{}text error message is {}", logPrefix, textErrorMessage)
        return textErrorMessage
    }
}