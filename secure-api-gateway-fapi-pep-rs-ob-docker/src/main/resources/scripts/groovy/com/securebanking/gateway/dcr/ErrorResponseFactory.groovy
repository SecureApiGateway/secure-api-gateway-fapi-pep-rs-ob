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
package com.securebanking.gateway.dcr

import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Factory which creates Response objects for error states when validating a DCR (Dynamic Client Registration) request
 */
class ErrorResponseFactory {

    static String INVALID_CLIENT_METADATA_ERROR_CODE = "invalid_client_metadata"
    static String INVALID_SOFTWARE_STATEMENT_ERROR_CODE = "invalid_software_statement"
    static String INVALID_REDIRECT_URI_ERROR_CODE = "invalid_redirect_uri"

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
        return errorResponse(Status.BAD_REQUEST, INVALID_CLIENT_METADATA_ERROR_CODE, errorMessage)
    }

    def invalidSoftwareStatementErrorResponse(errorMessage) {
        return errorResponse(Status.BAD_REQUEST, INVALID_SOFTWARE_STATEMENT_ERROR_CODE, errorMessage)
    }

    def invalidRedirectUriErrorResponse(errorMessage) {
        return errorResponse(Status.BAD_REQUEST, INVALID_REDIRECT_URI_ERROR_CODE, errorMessage)
    }

    def errorResponse(httpCode, errorMessage) {
        return errorResponse(httpCode, null, errorMessage)
    }

    Response errorResponse(httpCode, errorCode, errorMessage) {
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