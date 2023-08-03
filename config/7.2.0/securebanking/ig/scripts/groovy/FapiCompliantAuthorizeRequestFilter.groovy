import com.forgerock.sapi.gateway.rest.content.ContentTypeFormatterFactory
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.http.protocol.Status
import com.forgerock.sapi.gateway.jwt.JwtClaimNames
import com.forgerock.sapi.gateway.rest.HttpRequestParameterNames
import com.forgerock.sapi.gateway.rest.HttpHeaderNames
import com.forgerock.sapi.gateway.oauth.OAuthErrorResponseFactory


/**
 * This script checks that the call to the /authorize endpoint is
 * correctly formed and valid.
 *
 * Relevant specifications:
 * OAuth 2.0 spec: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
 * FAPI Part 1: https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server
 * FAPI Part 2: https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server
 *
 *
 */

def fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID)
if (fapiInteractionId == null) fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID
SCRIPT_NAME = '[FapiCompliantAuthorizeRequestFilter] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

String httpMethod = request.method
Header acceptHeader = request.getHeaders().get('accept')
ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory()

OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(SCRIPT_NAME, contentTypeFormatterFactory)

switch (httpMethod.toUpperCase()) {
    case 'GET':
    case 'POST':
        // Parse incoming registration JWT
        logger.debug(SCRIPT_NAME + 'Parsing authorize request')

        // From the OAuth 2.0 Spec:
        //   If the request fails due to a missing, invalid, or mismatching
        //   redirection URI, or if the client identifier is missing or invalid,
        //   the authorization server SHOULD inform the resource owner of the
        //   error and MUST NOT automatically redirect the user-agent to the
        //   invalid redirection URI.
        //
        // From the FAPI Part 1 Spec:
        //   Shall only use the parameters included in the signed request object passed via the request or request_uri
        //   parameter
        JwtClaimsSet requestJwtClaimSet = getRequestJtwClaimSet()
        if (!requestJwtClaimSet) {
            String errorDescription = "Request must have a 'request' query parameter the value of which must be a signed jwt"
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription)
        }

        Response errorResponse = isRequestValidForRedirection(requestJwtClaimSet, acceptHeader, errorResponseFactory)
        if (errorResponse) {
            return errorResponse
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
        String[] requiredClaims = [ JwtClaimNames.SCOPE, JwtClaimNames.NONCE, JwtClaimNames.RESPONSE_TYPE ]
        for (requiredClaim in requiredClaims) {
            if (!requestJwtHasClaim(requiredClaim, requestJwtClaimSet)) {
                String errorDescription = "Request JWT must have a '" + requiredClaim + "' claim"
                return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription)
            }
        }

        // Should be ignoring and not returning state if it only exists as a http request parameter and does not
        // exist in the request jwt. AM however doesn't apply this rule and returns state in the resulting redirect
        //
        // The solution is to remove it from the request sent to AM so that there is no state supplied.
        removeStateFromRequestIfNotInRequestJwt(requestJwtClaimSet)

        break
    default:
        logger.debug(SCRIPT_NAME + 'Method not supported')
        return new Response(Status.METHOD_NOT_ALLOWED)
}

logger.info('Request is FAPI compliant - calling next.handle')
return next.handle(context, request)

/**
 * Checks if we have sufficient trust to be able to send errors to the redirect_uri. Currently this 
 * not very useful as we have done no validation of the SSA signature, so we must return all subsequent
 * errors to the original caller rather than calling the redirect_uri. However it does at least serve
 * as a requirement should AM ever use this script as a basis for building FAPI compliant settings for
 * the authorization endpoint... or maybe if the become a problem we can build SSA validation into the 
 * as-authorize route config before calling this script so we can trust the SSA. Then we could change
 * subsequent error handling to add the error fields to the redirect_uri.
 */
private Response isRequestValidForRedirection(JwtClaimsSet requestJwtClaims,
                                              Header acceptHeader, OAuthErrorResponseFactory errorResponseFactory) {
    String[] requiredClaims = [ JwtClaimNames.REDIRECT_URI, JwtClaimNames.CLIENT_ID ]
    for ( requiredClaim in requiredClaims ) {
        if (!requestJwtHasClaim(requiredClaim, requestJwtClaims) ) {
            String errorDescription = "Request JWT must have a '" + requiredClaim + "' claim"
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription)
        }
    }
    return null
}

/**
 * Checks if the claim exists in the requestJwtClaimSet
 */
private Boolean requestJwtHasClaim(String claimName, JwtClaimsSet requestJwtClaims) {
    return requestJwtClaims.getClaim(claimName) ? true : false
}


private void removeStateFromRequestIfNotInRequestJwt(JwtClaimsSet requestJwtClaimSet) {
    String stateClaimName = 'state'
    if (!requestJwtHasClaim(stateClaimName, requestJwtClaimSet)) {
        String stateQueryParam = getQueryParamFromRequest(stateClaimName)
        if (stateQueryParam) {
            logger.info("{}Removing state request parameter as no state claim in request jwt", SCRIPT_NAME)
            Form existingQueryParams = request.getQueryParams()
            existingQueryParams.remove(stateClaimName)
            existingQueryParams.toRequestQuery(request)
        }
    }
}

private JwtClaimsSet getRequestJtwClaimSet() {
    String requestJwtString  = getQueryParamFromRequest(HttpRequestParameterNames.REQUEST)
    if (!requestJwtString) {
        logger.info('{}/authorize request must have a request query parameter', SCRIPT_NAME)
        return null
    }
    try {
        SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class)
        return jwt.getClaimsSet()
    }
    catch (e) {
        logger.info(SCRIPT_NAME + 'BAD_REQUEST: Could not parse request JWT string', e)
        return null
    }
}

/**
 *  Returns null if the parameter does not exist. Throws IllegalStateException if more than one query parameter with
 *  this name exists
 */
private String getQueryParamFromRequest(String paramName) {
    logger.debug("{}Obtaining query param with name '{}' from request", SCRIPT_NAME, paramName)
    String[] value = request.getQueryParams().get(paramName)

    if ( !value ) {
        logger.info("{} No query parameter of name '{}' exists in the request", SCRIPT_NAME, paramName)
        return null
    }

    if ( value.size() != 1 ) {
        logger.info("{}There are '{}' values for request parameter '{}'", SCRIPT_NAME, value.size(), paramName)
        return null
    }
    logger.debug("{} Value of query param '{}' is '{}'", SCRIPT_NAME, paramName, value)
    return value[0]
}

