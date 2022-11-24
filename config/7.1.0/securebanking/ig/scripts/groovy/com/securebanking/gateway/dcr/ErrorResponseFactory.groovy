package com.securebanking.gateway.dcr

import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Factory which creates Response objects for error states when validating a DCR (Dynamic Client Registration) request
 */
class ErrorResponseFactory {

    private final Logger logger = LoggerFactory.getLogger(getClass())
    /**
     * Prefix for log messages created by this factory.
     * This is allows the x-fapi-interaction-id to be logged.
     */
    private final String logPrefix

    public ErrorResponseFactory(String logPrefix) {
        this.logPrefix = logPrefix
    }

    def invalidClientMetadataErrorResponse(errorMessage) {
        return errorResponse(Status.BAD_REQUEST, "invalid_client_metadata", errorMessage)
    }

    def invalidSoftwareStatementErrorResponse(errorMessage) {
        return errorResponse(Status.BAD_REQUEST, "invalid_software_statement", errorMessage)
    }

    def invalidRedirectUriErrorResponse(errorMessage) {
        return errorResponse(Status.BAD_REQUEST, "invalid_redirect_uri", errorMessage)
    }

    def errorResponse(httpCode, errorMessage) {
        return errorResponse(httpCode, null, errorMessage)
    }

    def errorResponse(httpCode, errorCode, errorMessage) {
        def errorMsgJson = new LinkedHashMap()
        if (errorCode) {
            errorMsgJson["error"] = errorCode
        }
        errorMsgJson["error_description"] = errorMessage
        logger.warn("{}DCR failed, http status: {}, error: {}", logPrefix, httpCode, errorMsgJson)
        def response = new Response(httpCode)
        response.entity.setJson(errorMsgJson)
        return response
    }
}