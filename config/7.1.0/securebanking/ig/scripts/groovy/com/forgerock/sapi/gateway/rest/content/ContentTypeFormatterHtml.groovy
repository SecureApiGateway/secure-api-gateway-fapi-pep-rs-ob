package com.forgerock.sapi.gateway.rest.content

import org.slf4j.Logger
import org.slf4j.LoggerFactory

class ContentTypeFormatterHtml implements ContentTypeFormatter {

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final String logPrefix

    public ContentTypeFormatterHtml(String logPrefix) {
        this.logPrefix = logPrefix
    }

    String getFormattedResponse(Form errorForm) {
        logger.debug("{}getHtmlErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        StringBuilder errorMessageBuilder = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorization Error" +
                "</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>")
        errorForm.forEach((key, val) -> {
            logger.debug("{}processing entry for {}, val is {}", logPrefix, key, val)
            errorMessageBuilder.append("<p><b>" + key + ":</b> ")
            List<String> values = val

            Boolean first = true
            values.forEach((innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if (first) {
                    first = false
                } else {
                    errorMessageBuilder.append(', ')
                }
                errorMessageBuilder.append(innerVal)
            })
            errorMessageBuilder.append('</p>')
        })
        errorMessageBuilder.append("</body></html>")
        String htmlErrorMessage = errorMessageBuilder.toString()
        logger.debug("{}html error message is {}", logPrefix, htmlErrorMessage)
        return htmlErrorMessage
    }
}