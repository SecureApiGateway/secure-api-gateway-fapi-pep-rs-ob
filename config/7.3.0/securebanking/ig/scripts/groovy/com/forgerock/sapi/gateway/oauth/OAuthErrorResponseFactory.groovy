package com.forgerock.sapi.gateway.oauth

import com.forgerock.sapi.gateway.rest.content.ContentTypeFormatter
import com.forgerock.sapi.gateway.rest.content.ContentTypeFormatterFactory
import com.forgerock.sapi.gateway.rest.content.ContentTypeNegotiator
import com.forgerock.sapi.gateway.rest.HttpMediaTypes

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Factory which creates Response objects for OAuth2 releated errors as described in the following specifications:
 * https://www.rfc-editor.org/rfc/rfc6749#section-5.2
 */
class OAuthErrorResponseFactory {

    List<String> supportedMediaTypes = [ HttpMediaTypes.TEXT_HTML, HttpMediaTypes.APPLICATION_TEXT,
        HttpMediaTypes.APPLICATION_JSON, HttpMediaTypes.APPLICATION_FORM_URLENCODED, HttpMediaTypes.ALL_TYPES ]

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final ContentTypeNegotiator contentTypeNegotiator;

    private static final String INVALID_REQUEST = "invalid_request"
    private static final String INVALID_CLIENT = "invalid_client"
    private static final String INVALID_GRANT = "invalid_grant"
    private static final String UNAUTHORIZED_CLIENT = "unauthorized_client"
    private static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    private static final String INVALID_SCOPE = "invalid_scope"

    /**
     * Prefix for log messages created by this factory.
     * This is allows the x-fapi-interaction-id to be logged.
     */
    private final String logPrefix
    private final ContentTypeFormatterFactory messageFormatterFactory

    public OAuthErrorResponseFactory(String logPrefix, ContentTypeFormatterFactory messageFormatterFactory) {
        this.logPrefix = logPrefix
        this.supportedMediaTypes = supportedMediaTypes
        this.contentTypeNegotiator = new ContentTypeNegotiator(logPrefix, supportedMediaTypes)
        this.messageFormatterFactory = messageFormatterFactory
    }

    Response invalidRequestErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_REQUEST, acceptHeader, errorDescription)
    }

    Response invalidClientErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_CLIENT, acceptHeader, errorDescription)
     }

     Response invalidGrantErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_GRANT, acceptHeader, errorDescription)
     }

     Response unauthorizedClientErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(UNAUTHORIZED_CLIENT, acceptHeader, errorDescription)
     }

    Response unsupportedGrantTypeErrorResponse(Header acceptHeader, String errorDescription){
        return createErrorResponse(UNSUPPORTED_GRANT_TYPE, acceptHeader, errorDescription)
    }

     Response invalidScopeErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_SCOPE, acceptHeader, errorDescription)
     }

    Response createErrorResponse(String errorType, Header acceptHeader, String errorDescription){
        String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
        Form errorForm = new Form()
        errorForm.add("error", errorType)
        errorForm.add("error_description", errorDescription)
        return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
    }

    Response errorResponse(Status httpCode, Form errorForm, String bestContentType) {
        String errorMessage = getErrorMessage(errorForm, bestContentType)
        logger.info("{} creating OAuth Error Response, http status: {}, error: {}", logPrefix, httpCode, errorMessage)
        Response response = new Response(httpCode)
        response.entity.setString(errorMessage)
        ContentTypeHeader mediaTypeHeader = new ContentTypeHeader(bestContentType, [:])
        response.addHeaders(mediaTypeHeader)
        return response
    }

    String getErrorMessage(Form errorForm, String bestContentType) {
        ContentTypeFormatter formatter = messageFormatterFactory.getContentTypeFormatter(bestContentType, logPrefix)
        return formatter.getFormattedResponse(errorForm)
    }
}