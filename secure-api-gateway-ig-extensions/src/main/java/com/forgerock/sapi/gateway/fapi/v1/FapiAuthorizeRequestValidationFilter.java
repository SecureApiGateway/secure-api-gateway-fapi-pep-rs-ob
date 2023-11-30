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
package com.forgerock.sapi.gateway.fapi.v1;

import java.util.List;
import java.util.Set;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.error.OAuthErrorResponseFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;

/**
 * Validates that a request made to the OAuth2.0 /authorize endpoint is FAPI compliant.
 *
 * OAuth 2.0 spec: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
 * FAPI Part 1: https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server
 * FAPI Part 2: https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server
 */
public class FapiAuthorizeRequestValidationFilter implements Filter {

    private static final Set<String> VALID_HTTP_REQUEST_METHODS = Set.of("POST", "GET");
    private static final List<String> REQUIRED_REQUEST_JWT_REDIRECT_CLAIMS = List.of("redirect_uri", "client_id");
    private static final List<String> REQUIRED_REQUEST_JWT_CLAIMS = List.of("scope", "nonce", "response_type");

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALID_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return Promises.newResultPromise(new Response(Status.METHOD_NOT_ALLOWED));
        }

        final Header acceptHeader = request.getHeaders().get("accept");
        final JwtClaimsSet requestJwtClaimSet = getRequestJwtClaimSet(request);
        if (requestJwtClaimSet == null) {
            final String errorDescription = "Request must have a 'request' query parameter the value of which must be a signed jwt";
            return Promises.newResultPromise(errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription));
        }
        Response errorResponse = isRequestValidForRedirection(requestJwtClaimSet, acceptHeader);
        if (errorResponse != null) {
            return Promises.newResultPromise(errorResponse);
        }

        // ToDo - any failures of tests after this point should result in errors being sent to the redirect URI.
        // However, we haven't yet validated the requestJwt so we can't truly trust it. We leave AM to do the
        // JWT validation.
        // The OAuth spec says this about errors:
        //   If the resource owner denies the access request or if the request
        //   fails for reasons other than a missing or invalid redirection URI,
        //   the authorization server informs the client by adding the following
        //   parameters to the query component of the redirection URI using the
        //   "application/x-www-form-urlencoded" format, per Appendix B:
        // However, the FAPI Advanced Part 1 compliance suite indicates that it is OK to simply show an error in
        // response to the request - which is what we will do for now. These tests really need to be rolled into
        // ForgeRock AM as a FAPI compliant option.

        // Spec covering the necessity of these fields to exist in the authorization request:
        // scope - The FAPI Advanced part 1 spec, section 5.2.2.1 states that
        //   "if it is desired to provide the  authenticated user's identifier to the client
        //   in the token response, the authorization server:
        //   1. shall support the authentication request as in Section 3.1.2.1 of OIDC
        //   (see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
        //
        // The OIDC spec states that scope, response_type, client_id and redirect are required.
        // -------------------------
        // FAPI Advanced Part 1, part 5.2.2.3
        //   "1. shall require the nonce parameter defined in Section 3.1.2.1 of OIDC in the authentication request"
        // (see https://openid.net/specs/openid-financial-api-part-1-1_0.html#client-requesting-openid-scope)
        for (String requiredClaim : REQUIRED_REQUEST_JWT_CLAIMS) {
            if (!requestJwtHasClaim(requiredClaim, requestJwtClaimSet)) {
                String errorDescription = "Request JWT must have a '" + requiredClaim + "' claim";
                return Promises.newResultPromise(errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription));
            }
        }

        // Should be ignoring and not returning state if it only exists as a http request parameter and does not
        // exist in the request jwt. AM however doesn't apply this rule and returns state in the resulting redirect
        //
        // The solution is to remove it from the request sent to AM so that there is no state supplied.
        removeStateFromRequestIfNotInRequestJwt(request, requestJwtClaimSet);
        logger.debug("/authorize request is FAPI compliant");

        return next.handle(context, request);
    }

    private JwtClaimsSet getRequestJwtClaimSet(Request request) {
        final String requestJwtString = getQueryParamFromRequest(request, "request");
        if (requestJwtString == null) {
            logger.info("/authorize request must have a request query parameter");
            return null;
        }
        try {
            SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class);
            return jwt.getClaimsSet();
        }
        catch (RuntimeException ex) {
            logger.info("BAD_REQUEST: Could not parse request JWT string", ex);
            return null;
        }
    }

    /**
     *  Returns null if the parameter does not exist. Throws IllegalStateException if more than one query parameter with
     *  this name exists
     */
    private String getQueryParamFromRequest(Request request, String paramName) {
        logger.debug("Obtaining query param with name '{}' from request", paramName);
        final List<String> value = request.getQueryParams().get(paramName);
        if (value == null) {
            logger.info("No query parameter of name '{}' exists in the request", paramName);
            return null;
        }
        if (value.size() != 1) {
            logger.info("There are '{}' values for request parameter '{}'", value.size(), paramName);
            return null;
        }
        logger.debug("Value of query param '{}' is '{}'", paramName, value);
        return value.get(0);
    }

    /**
     * Checks if we have sufficient trust to be able to send errors to the redirect_uri. Currently, this
     * not very useful as we have done no validation of the SSA signature, so we must return all subsequent
     * errors to the original caller rather than calling the redirect_uri. However, it does at least serve
     * as a requirement should AM ever use this script as a basis for building FAPI compliant settings for
     * the authorization endpoint... or maybe if the become a problem we can build SSA validation into the
     * as-authorize route config before calling this script so we can trust the SSA. Then we could change
     * subsequent error handling to add the error fields to the redirect_uri.
     */
    private Response isRequestValidForRedirection(JwtClaimsSet requestJwtClaims, Header acceptHeader) {
        for (String requiredClaim : REQUIRED_REQUEST_JWT_REDIRECT_CLAIMS ) {
            if (!requestJwtHasClaim(requiredClaim, requestJwtClaims) ) {
                String errorDescription = "Request JWT must have a '" + requiredClaim + "' claim";
                return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription);
            }
        }
        return null;
    }

    /**
     * Checks if the claim exists in the requestJwtClaimSet
     */
    private boolean requestJwtHasClaim(String claimName, JwtClaimsSet requestJwtClaims) {
        return requestJwtClaims.getClaim(claimName) != null;
    }

    private void removeStateFromRequestIfNotInRequestJwt(Request request, JwtClaimsSet requestJwtClaimSet) {
        String stateClaimName = "state";
        if (!requestJwtHasClaim(stateClaimName, requestJwtClaimSet)) {
            String stateQueryParam = getQueryParamFromRequest(request, stateClaimName);
            if (stateQueryParam != null) {
                logger.info("Removing state request parameter as no state claim in request jwt");
                Form existingQueryParams = request.getQueryParams();
                existingQueryParams.remove(stateClaimName);
                existingQueryParams.toRequestQuery(request);
            }
        }
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiAuthorizeRequestValidationFilter();
        }
    }

}
