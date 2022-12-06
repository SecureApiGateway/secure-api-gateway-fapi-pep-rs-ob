/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.dcr;

import org.forgerock.util.Reject;

/**
 * Exception for modelling DCR Validation Errors.
 *
 * This exception contains errorCode and errorDescription fields which can be used to produce an error response which adheres
 * to OAuth 2.0 Dynamic Client Registration Protocol spec: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
 */
public class ValidationException extends RuntimeException {

    public enum ErrorCode {
        INVALID_REDIRECT_URI("invalid_redirect_uri"),
        INVALID_CLIENT_METADATA("invalid_client_metadata"),
        INVALID_SOFTWARE_STATEMENT("invalid_software_statement"),
        UNAPPROVED_SOFTWARE_STATEMENT("unapproved_software_statement");

        private final String code;

        ErrorCode(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }

    private final ErrorCode errorCode;
    private final String errorDescription;

    public ValidationException(ErrorCode errorCode, String errorMessage) {
        this(errorCode, errorMessage, null);
    }

    public ValidationException(ErrorCode errorCode, String errorMessage, Throwable cause) {
        super((errorCode != null ? errorCode.code : "") + " " + errorMessage, cause);
        this.errorCode = Reject.checkNotNull(errorCode, "errorCode must be supplied");
        this.errorDescription = Reject.checkNotBlank(errorMessage, "errorMessage must be supplied");
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
