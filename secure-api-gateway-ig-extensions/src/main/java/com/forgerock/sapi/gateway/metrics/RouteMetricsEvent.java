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
package com.forgerock.sapi.gateway.metrics;

import java.util.Map;

/**
 * RouteMetricsEvent represents the metrics data gathered when a request has been processed by a particular route
 */
public class RouteMetricsEvent {

    /**
     * Unix epoch timestamp in milliseconds representing the time at which the event was created
     */
    private long timestamp;
    /**
     * Description of the type of this event e.g. route-metrics
     */
    private String eventType;
    /**
     * IG routeId of the route which produced the event
     */
    private String routeId;
    /**
     * Path portion of the request URI
     */
    private String requestPath;
    /**
     * HTTP method of the request
     */
    private String httpMethod;
    /**
     * Time to process the request and produce a response
     */
    private long responseTimeMillis;
    /**
     * HTTP Status Code of the response
     */
    private int httpStatusCode;
    /**
     * Flag indicating if the httpStatusCode represents a success or not.
     */
    private boolean successResponse;
    /**
     * The id of the ApiClient making the request
     */
    private String apiClientId;
    /**
     * The id of the ApiClientOrganisation that the ApiClient belongs to
     */
    private String apiClientOrgId;
    /**
     * Name of the trustedDirectory that the ApiClient is registered with
     */
    private String trustedDirectory;
    /**
     * Custom contextual information which may be supplied on a per-request basis
     */
    private Map<String, Object> context;

    public long getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getRouteId() {
        return routeId;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public long getResponseTimeMillis() {
        return responseTimeMillis;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public boolean isSuccessResponse() {
        return successResponse;
    }

    public String getApiClientId() {
        return apiClientId;
    }

    public String getApiClientOrgId() {
        return apiClientOrgId;
    }

    public String getTrustedDirectory() {
        return trustedDirectory;
    }

    public Map<String, Object> getContext() {
        return context;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public void setRouteId(String routeId) {
        this.routeId = routeId;
    }

    public void setRequestPath(String requestPath) {
        this.requestPath = requestPath;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public void setResponseTimeMillis(long responseTimeMillis) {
        this.responseTimeMillis = responseTimeMillis;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public void setSuccessResponse(boolean successResponse) {
        this.successResponse = successResponse;
    }

    public void setApiClientId(String apiClientId) {
        this.apiClientId = apiClientId;
    }

    public void setApiClientOrgId(String apiClientOrgId) {
        this.apiClientOrgId = apiClientOrgId;
    }

    public void setTrustedDirectory(String trustedDirectory) {
        this.trustedDirectory = trustedDirectory;
    }

    public void setContext(Map<String, Object> context) {
        this.context = context;
    }
}
