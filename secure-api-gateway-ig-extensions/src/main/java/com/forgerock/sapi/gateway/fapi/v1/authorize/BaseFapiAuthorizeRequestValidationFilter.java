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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import java.util.List;
import java.util.Set;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.error.OAuthErrorResponseFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.HttpHeaderNames;

/**
 * Base class for validating that authorize requests are FAPI compliant.
 * <p>
 * This class can be extended to provide implementations which are specific to particular OAuth2.0 endpoints that
 * handle such requests, namely: /authorize and /par
 * <p>
 * Specs:
 * <ul>
 *     <li><a href="https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server">FAPI Part 1</a></li>
 *     <li><a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">FAPI Part 2</a></li>
 * </ul>
 */
public abstract class BaseFapiAuthorizeRequestValidationFilter implements Filter {
    private static final Set<String> VALID_HTTP_REQUEST_METHODS = Set.of("POST", "GET");
    private static final List<String> REQUIRED_REQUEST_JWT_CLAIMS = List.of("scope", "nonce", "response_type", "redirect_uri", "client_id");
    protected static final String STATE_PARAM_NAME = "state";
    private static final String REQUEST_JWT_PARAM_NAME = "request";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Factory capable of producing OAuth2.0 compliant HTTP Responses for error conditions.
     */
    protected final OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());

    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALID_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return Promises.newResultPromise(new Response(Status.METHOD_NOT_ALLOWED));
        }

        final Header acceptHeader = request.getHeaders().get(HttpHeaderNames.ACCEPT);
        return getRequestJwtClaimSet(request).thenAsync(requestJwtClaimSet -> {
            if (requestJwtClaimSet == null) {
                final String errorDescription = "Request must have a 'request' parameter the value of which must be a signed jwt";
                return Promises.newResultPromise(errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription));
            }
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
            return removeStateFromRequestIfNotInRequestJwt(request, requestJwtClaimSet)
                    .thenAsync(noResult -> {
                        logger.info("Authorize request is FAPI compliant");
                        return next.handle(context, request);
                    });
        });
    }

    private Promise<JwtClaimsSet, NeverThrowsException> getRequestJwtClaimSet(Request request) {
        return getParamFromRequest(request, REQUEST_JWT_PARAM_NAME).then(requestJwtString -> {
            if (requestJwtString == null) {
                logger.info("authorize request must have a request JWT parameter");
                return null;
            }
            try {
                SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class);
                return jwt.getClaimsSet();
            } catch (RuntimeException ex) {
                logger.info("BAD_REQUEST: Could not parse request JWT string", ex);
                return null;
            }
        });
    }

    protected Promise<Void, NeverThrowsException> removeStateFromRequestIfNotInRequestJwt(Request request, JwtClaimsSet requestJwtClaimSet) {
        if (!requestJwtHasClaim(STATE_PARAM_NAME, requestJwtClaimSet)) {
            return getParamFromRequest(request, STATE_PARAM_NAME).thenOnResult(stateParam -> {
                if (stateParam != null) {
                    logger.info("Removing state request parameter as no state claim in request jwt");
                    removeStateParamFromRequest(request);
                }
            }).thenDiscardResult();
        }
        return Promises.newVoidResultPromise();
    }

    /**
     * Retrieves a parameter from the HTTP Request.
     *
     * @param request   Request the HTTP Request to retrieve the parameter from
     * @param paramName String the name of the parameter
     * @return Promise<String, NeverThrowsException> which returns the param value as a String or a null if the param
     * does not exist or fails to be retrieved due to an exception.
     */
    protected abstract Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName);

    /**
     * Removes the state parameter from the Request.
     * <p>
     * See removeStateFromRequestIfNotInRequestJwt for usage, this is required to work around an issue in AM
     *
     * @param request Request the HTTP Request to remove the state param from.
     */
    protected abstract void removeStateParamFromRequest(Request request);

    /**
     * Checks if the claim exists in the requestJwtClaimSet
     */
    protected boolean requestJwtHasClaim(String claimName, JwtClaimsSet requestJwtClaims) {
        return requestJwtClaims.getClaim(claimName) != null;
    }

}
