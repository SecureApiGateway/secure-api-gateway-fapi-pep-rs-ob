/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.dcr.idm;

import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;

/**
 * Service which retrieves an ApiClient
 */
public interface ApiClientService {

    class ApiClientServiceException extends Exception {

        public enum ErrorCode {
            DELETED,
            NOT_FOUND,
            DECODE_FAILED,
            SERVER_ERROR;
        }
        private final ErrorCode errorCode;

        public ApiClientServiceException(ErrorCode errorCode, String message) {
            this(errorCode, message, null);

        }

        public ApiClientServiceException(ErrorCode errorCode, String message, Throwable cause) {
            super(message, cause);
            Reject.ifNull(errorCode, "errorCode must be supplied");
            this.errorCode = errorCode;
        }

        public ErrorCode getErrorCode() {
            return errorCode;
        }

        @Override
        public String getMessage() {
            return "[" + errorCode.name() + "] " + super.getMessage();
        }
    }


    /**
     * Gets an {@link ApiClient} by their clientId
     * @param clientId the OAuth2 client_id of the ApiClient
     * @return Promise which either returns the ApiClient or an ApiClientServiceException if an error occurs.
     */
    Promise<ApiClient, ApiClientServiceException> getApiClient(String clientId);
}
