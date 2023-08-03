package com.forgerock.sapi.gateway.rest.content

interface ContentTypeFormatter {
    String getFormattedResponse(Form errorForm)
}