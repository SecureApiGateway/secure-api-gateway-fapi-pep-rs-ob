package com.forgerock.sapi.gateway.rest.content

import com.forgerock.sapi.gateway.rest.HttpMediaTypes

class ContentTypeFormatterFactory{
    ContentTypeFormatter getContentTypeFormatter(String httpMediaType, String logPrefix){
        if(httpMediaType == HttpMediaTypes.TEXT_HTML) {
            return new ContentTypeFormatterHtml(logPrefix)
        } else if (httpMediaType == HttpMediaTypes.APPLICATION_FORM_URLENCODED) {
            return new ContentTypeFormatterFormUrlEncoded(logPrefix)
        } else if (httpMediaType == HttpMediaTypes.APPLICATION_TEXT) {
            return new ContentTypeFormatterText(logPrefix)
        } else {
            return new ContentTypeFormatterJson(logPrefix)
        }
    }
}