import static java.lang.String.format
import static java.util.Objects.requireNonNull
import static org.forgerock.json.jose.utils.JoseSecretConstraints.allowedAlgorithm
import static org.forgerock.openig.fapi.dcr.common.DcrErrorCode.UNKNOWN
import static org.forgerock.openig.fapi.error.ErrorResponseUtils.errorResponseAsync
import static org.forgerock.openig.fapi.jwks.JwkSetServicePurposes.signingPurpose
import static org.forgerock.openig.tools.jwt.validation.Constraints.isInThePast;
import static org.forgerock.openig.tools.jwt.validation.Result.failure
import static org.forgerock.openig.tools.jwt.validation.Result.success
import static org.forgerock.util.promise.NeverThrowsException.neverThrown


import java.time.Instant

import javax.swing.SpringLayout

// OPENIG-9436: Use local reimplementation of JwtReconstruction to handle XML payloads
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.openig.fapi.jwt.OctetSequenceJwsReconstruction

import org.forgerock.json.jose.exceptions.InvalidJwtException
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.openig.fapi.apiclient.ApiClient
import org.forgerock.openig.fapi.apiclient.ApiClientFapiContext
import org.forgerock.openig.tools.jwt.validation.JwtConstraint
import org.forgerock.openig.tools.jwt.validation.JwtValidator
import org.forgerock.openig.tools.jwt.validation.JwtValidatorResult
import org.forgerock.openig.tools.jwt.validation.Violation
import org.forgerock.secrets.Purpose
import org.forgerock.secrets.SecretsProvider
import org.forgerock.secrets.jwkset.JwkSetSecretStore
import org.forgerock.secrets.keys.VerificationKey
import org.forgerock.util.time.Duration

import groovy.json.JsonSlurper

/**
 * Process file payment and consent requests where the data is represented in the request entity (rather than the JWS
 * payload), and verified using a detached signature in the JWS header.
 *
 * Subject to waiver for earlier versions as per spec:
 * <a href="https://openbanking.atlassian.net/wiki/spaces/DZ/pages/1112670669/W007">Open Banking waiver 007</a>
 *
 * If ASPSPs are still using v3.1.3 or earlier, they must support the parameter b64 to be false,
 * and any TPPs using these ASPSPs must do the same.
 *
 * If ASPSPs have updated to v3.1.4 or later, they must not include the b64 claim in the header,
 * and any TPPs using these ASPSPs must do the same.
 *
 * See also: <a href="https://www.rfc-editor.org/rfc/rfc7515#page-7">the JWS spec</a> and
 * example detached payloads in <a href=
 * "https://openbankinguk.github.io/read-write-api-site3/v4.0/references/usage-examples/file-payments-usage-examples.html"
 * >Open Banking Read/ Write API for file payments</a>.
 */

SCRIPT_NAME = null
IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"
SUPPORTED_SIGNING_ALGORITHMS = List.of("PS256")
PRE_3_1_4_VERSIONS = [ 'v3.0', 'v3.1.0', 'v3.1.1', 'v3.1.2', 'v3.1.3' ]

/**
 * ProcessDetachedSig-specific Exception.
 */
class ProcessDetachedSigException extends Exception {
    @Serial
    private static final long serialVersionUID = 1L;

    private String errorDescription

    /**
     * Constructs a new {@link ProcessDetachedSigException}.
     * @param errorDescription the error description
     * @param cause the cause
     */
    ProcessDetachedSigException(final String errorDescription) {
        this.errorDescription = requireNonNull(errorDescription)
    }

    String getErrorDescription() {
        return errorDescription;
    }
}

scriptInit(request)
filter(context, request, next)

/**
 * Initialises the script.
 * @param request the request
 */
void scriptInit(Request request) {
    def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
    if (fapiInteractionId == null) {
        fapiInteractionId = "No x-fapi-interaction-id"
    }
    jwtReconstruction = new JwtReconstruction().recognizedHeaders(IAT_CRIT_CLAIM, ISS_CRIT_CLAIM, TAN_CRIT_CLAIM)
    octetSequenceReconstruction = new OctetSequenceJwsReconstruction().recognizedHeaders(IAT_CRIT_CLAIM, ISS_CRIT_CLAIM, TAN_CRIT_CLAIM)
    SCRIPT_NAME = "[ProcessDetachedSig] (" + fapiInteractionId + ") - "
    logger.debug(SCRIPT_NAME + "Running...")
}

/**
 * Script filter method
 * @param context the context
 * @param request the request
 * @param next the next handler
 * @return A promise containing a response
 */
Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
    validateArgs()

    // routeArgClockSkewAllowance is a org.forgerock.util.time.Duration
    // (see docs: https://backstage.forgerock.com/docs/ig/2024.3/reference/preface.html#definition-duration)
    clockSkewAllowance = Duration.duration(routeArgClockSkewAllowance).toJavaDuration()
    logger.debug(SCRIPT_NAME + "Configured clock skew allowance: " + clockSkewAllowance)

    def method = request.method
    if (method != "POST") {
        //This script should be executed only if it is a POST request
        logger.debug(SCRIPT_NAME + "Skipping the filter because the method is not POST, the method is " + method)
        return next.handle(context, request)
    }

    def contentType = request.headers.getFirst(ContentTypeHeader.NAME)
    logger.debug(SCRIPT_NAME + "request.content-type: {}", (contentType != null ? contentType : "unset"))

    // Parse api version from the request path
    logger.debug(SCRIPT_NAME + "request.uri.path: {}", request.uri.path)
    String apiVersionRegex = "(v(\\d+.)?(\\d+.)?(\\*|\\d+))"
    def match = (request.uri.path =~ apiVersionRegex)
    def apiVersion = "";
    if (match.find()) {
        apiVersion = match.group(1)
        logger.debug(SCRIPT_NAME + "API version: {}", apiVersion)
    } else {
        return fail(Status.BAD_REQUEST, "Can't parse API version for inbound request")
    }

    logger.debug(SCRIPT_NAME + "Building JWT from detached header")
    // JWS detached signature pattern: 'JWSHeader..JWSSignature' with no JWS payload
    def jwsDetachedSignatureHeader = request.headers.get(routeArgHeaderName)
    if (jwsDetachedSignatureHeader == null) {
        return fail(Status.BAD_REQUEST, "No detached signature header on inbound request " + routeArgHeaderName)
    }

    String detachedSignatureValue = jwsDetachedSignatureHeader.firstValue.toString()
    logger.debug(SCRIPT_NAME + "Inbound detached signature: " + detachedSignatureValue)
    String[] signatureElements = detachedSignatureValue.split("\\.")
    if (signatureElements.length != 3) {
        return fail(Status.BAD_REQUEST,
                    "Wrong number of dots on inbound detached signature " + signatureElements.length)
    }
    // Get the JWS header, first part of array
    String jwsHeaderEncoded = signatureElements[0]

    // Check JWS header for b64 claim:
    // - If claim is present, and API version > 3.1.3 then reject
    // - If claim is present, and is set to false, and API < 3.1.4 then accept and validate as non base64 payload

    String jwsHeaderDecoded = new String(jwsHeaderEncoded.decodeBase64Url())
    logger.debug(SCRIPT_NAME + "Got JWT header: {}", jwsHeaderDecoded)
    def jwsHeaderDataStructure = new JsonSlurper().parseText(jwsHeaderDecoded)

    def isApiVersionPre314 = PRE_3_1_4_VERSIONS.contains(apiVersion)
    if (isApiVersionPre314) {
        //Processing pre v3.1.4 requests
        if (jwsHeaderDataStructure.b64 == null) {
            logger.error(SCRIPT_NAME + "B64 header must be presented in JWT header before v3.1.3")
            return fail(Status.UNAUTHORIZED, "Signature validation failed")
        } else if (jwsHeaderDataStructure.b64 != false) {
            logger.error(SCRIPT_NAME + "B64 header must be false in JWT header before v3.1.3")
            return fail(Status.UNAUTHORIZED, "Signature validation failed")
        }
        //Processing post v3.1.4 requests
    } else if (jwsHeaderDataStructure.b64 != null) {
        logger.error(SCRIPT_NAME + "B64 header not permitted in JWT header after v3.1.3")
        return fail(Status.UNAUTHORIZED, "Signature validation failed")
    }

    // Validate the signed-JWT (against the "sig" keys).
    String[] jwtElements = detachedSignatureValue.split("\\.")

    return request.entity.getStringAsync()
                  .then({requestPayload ->
                      logger.debug("Processing payload: {}", requestPayload)
                      if (isApiVersionPre314) {
                          return jwtElements[0] + "." + requestPayload + "." + jwtElements[2]
                      }
                      // v3.1.4 and higher - The payload must be encoded with base64Url
                      return jwtElements[0] + "." +
                              Base64.getUrlEncoder().withoutPadding().encodeToString(requestPayload.getBytes()) + "." +
                              jwtElements[2]
                  })
                  .then({rebuiltJwt ->
                      reconstructJwt(rebuiltJwt, contentType)
                  })
                  .thenAsync({signedJwt ->
                      // Validate the payload and verify sig with ApiClient signing key
                      apiClient().getJwkSetSecretStore()
                                 .thenAsync(jwkSetSecretStore -> validateJwt(signedJwt, jwkSetSecretStore))
                                 .thenAsync(ignored -> next.handle(context, request),
                                            sigException -> fail(Status.UNAUTHORIZED,
                                                                 sigException.getErrorDescription()))
                  },
                             jwtException -> fail(Status.BAD_REQUEST, jwtException.getErrorDescription())
    )
}

private SignedJwt reconstructJwt(String jwtString, String contentType)
        throws ProcessDetachedSigException {
    if (contentType == null) {
        logger.warn("Document received with unknown content type - assuming 'application/json'")
    }
    if (contentType == null || contentType.startsWith("application/json")) {
        // For JSON document payload, expect JWT claims representation
        try {
            return jwtReconstruction.reconstructJwt(jwtString, SignedJwt.class);
        } catch (InvalidJwtException invalidJwtException) {
            throw new ProcessDetachedSigException("Failed to parse JSON-based document payload" +
                                                          " - check supported formats and content type: " +
                                                          invalidJwtException.getMessage())
        }
    }
    if (contentType.startsWith("text/xml") || contentType.startsWith("text/plain")
            || contentType.startsWith("text/csv")) {
        // For XML document payload, manage through the octet-sequence representation - N.B. some customers may require
        // text and CSV batch file payment uploads.
        try {
            return octetSequenceReconstruction.reconstructJwt(jwtString)
        } catch (InvalidJwtException invalidJwtException) {
            throw new ProcessDetachedSigException("Failed to parse octet-sequence-based document payload" +
                                                          " - check supported formats and content type: " +
                                                          invalidJwtException.getMessage())
        }
    }
    logger.warn("Document received with unsupported content type {}", contentType)
}

private Promise<Void, ProcessDetachedSigException> validateJwt(final SignedJwt signedJwt,
                                                               final JwkSetSecretStore jwkSetSecretStore) {
    return buildJwtValidator(jwkSetSecretStore).report(signedJwt)
                                               .then(handleValidationResult(),
                                                     neverThrown())
}

private JwtValidator buildJwtValidator(jwkSetSecretStore) {
    return JwtValidator.builder(clock)
                       .withSkewAllowance(clockSkewAllowance)
                       .jwt(hasSupportedSigningAlgorithm())
                       .jwt(hasValidSignatureWithNamedKidOnly(jwkSetSecretStore))
                       .jwt(hasValidIssHeaderParameter())
                       .jwt(hasValidHeaderType())
                       .jwt(hasValidIatHeaderParameter())
                       .jwt(hasValidTanHeaderParameter())
                       .build()
}

private JwtConstraint hasValidSignatureWithNamedKidOnly(final JwkSetSecretStore jwkSetSecretStore) {
    // IG Constraints#hasValidSignature tests with named or falls back valid secrets, but for FAPI we want to
    // test only for the kid supplied in the JwsHeader
    SecretsProvider secretsProvider = new SecretsProvider(clock).setDefaultStores(jwkSetSecretStore)
    SigningManager signingManager = new SigningManager(secretsProvider)

    return { context ->
        if (context.getJwt() instanceof SignedJwt) {
            SignedJwt signedJwt = context.getJwt()
            JwsAlgorithm algorithm = signedJwt.getHeader().getAlgorithm()
            Purpose<VerificationKey> constrainedPurpose = signingPurpose().withConstraints(allowedAlgorithm(algorithm))
            String keyId = signedJwt.getHeader().getKeyId()
            return secretsProvider.getNamedSecret(requireNonNull(constrainedPurpose), keyId)
                                  .then(signingManager::newVerificationHandler)
                                  .then(signedJwt::verify)
                                  .then({result ->
                                      if (result) {
                                          return success()
                                      }
                                      logger.error(SCRIPT_NAME + "SignedJwt failed verification")
                                      return failure(new Violation("Expected JWT to have a valid signature"))
                                  })
                                  .thenCatch({nsse ->
                                      logger.error(SCRIPT_NAME + "Named secret not found for keyId {}", keyId, nsse)
                                      failure(new Violation("Expected JWT to have a valid signature"))
                                  })
        }
        logger.error(SCRIPT_NAME + "Supplied JWT is not a SignedJWT")
        return failure(new Violation("Expected JWT to have a valid signature")).asPromise()
    } as JwtConstraint
}

private JwtConstraint hasSupportedSigningAlgorithm() {
    return { context ->
        {
            def alg = context.getJwt().getHeader().getAlgorithmString()
            if (SUPPORTED_SIGNING_ALGORITHMS.contains(alg)) {
                return success().asPromise();
            }
            return failure(new Violation("Expected JWT to be signed using one of the supported 'alg' values: "
                                                 + SUPPORTED_SIGNING_ALGORITHMS)).asPromise();
        }
    } as JwtConstraint
}

/* Validate the "http://openbanking.org.uk/iss" claim.
 *
 * From the OB Spec:
 *   If the issuer is using a signing key lodged with a Trust Anchor, the value is defined by the Trust Anchor and
 *   should uniquely identify the PSP.
 *   For example, when using the Open Banking Directory, the value must be:
 *   - When issued by a TPP, of the form {{org-id}}/{{software-statement-id}},
 */
private JwtConstraint hasValidIssHeaderParameter() {
    return { context ->
        {
            def issCritClaim = context.getJwt().getHeader().getParameter(ISS_CRIT_CLAIM)
            if (issCritClaim == null) {
                return failure(new Violation(format("Expected value for header '%s' to be not null", ISS_CRIT_CLAIM))).
                        asPromise();
            }
            def apiClient = apiClient()
            def orgId = apiClient.getOrganisation().id()
            def softwareStatementId = apiClient.getSoftwareId()
            def expectedIssuerValue = orgId + "/" + softwareStatementId
            if (expectedIssuerValue != issCritClaim) {
                logger.error(SCRIPT_NAME + "Invalid " + ISS_CRIT_CLAIM +
                                     " value, expected: " + expectedIssuerValue +
                                     " actual: " + issCritClaim)
                return failure(new Violation(format("Expected value for header '%s' to be equal to %s",
                                                    ISS_CRIT_CLAIM,
                                                    expectedIssuerValue))).asPromise();
            }
            logger.debug(SCRIPT_NAME + ISS_CRIT_CLAIM + " is valid")
            return success().asPromise();
        }
    } as JwtConstraint
}

private JwtConstraint hasValidHeaderType() {
    //optional header - only if it's found verify that it's mandatory equal to "JOSE"
    return { context ->
        {
            def type = context.getJwt().getHeader().getType()
            if (type == null || "JOSE".equals(type.name())) {
                return success().asPromise()
            }
            return failure(new Violation("Expected value for type to be to 'JOSE'")).asPromise()
        }
    } as JwtConstraint
}

private JwtConstraint hasValidIatHeaderParameter() {
    return {context ->
        {
            def iatHeader = context.getJwt().getHeader().getParameter(IAT_CRIT_CLAIM)
            if (iatHeader == null) {
                logger.error(SCRIPT_NAME + "Could not validate detached JWT - required claim: " +
                                     IAT_CRIT_CLAIM + " " + "not found")
                return failure(new Violation(format("Expected value for '%s' to have a value", IAT_CRIT_CLAIM)))
                        .asPromise()
            }
            // Delegate time-based validation with skew...
            def iatTimestamp = Instant.ofEpochSecond(Long.valueOf(iatHeader))
            return isInThePast().apply(context, IAT_CRIT_CLAIM, iatTimestamp)
        }
    } as JwtConstraint
}

private JwtConstraint hasValidTanHeaderParameter() {
    return { context ->
        {
            def tanHeader = context.getJwt().getHeader().getParameter(TAN_CRIT_CLAIM)
            if (tanHeader == null || tanHeader != routeArgTrustedAnchor) {
                logger.error(SCRIPT_NAME + "Could not validate detached JWT - Invalid trusted anchor found: " +
                                     tanHeader + " expected: " + routeArgTrustedAnchor)
                return failure(new Violation(format("Expected value for '%s' to be to '%s'", TAN_CRIT_CLAIM,
                                                    routeArgTrustedAnchor))).asPromise()
            }
            return success().asPromise()
        }
    } as JwtConstraint
}

private Function<JwtValidatorResult, Void, ProcessDetachedSigException> handleValidationResult() {
    return { result ->
        {
            if (!result.isValid()) {
                logger.debug("Request JWT is invalid - constraint violations: {}", result.getViolationsAsString())
                throw new ProcessDetachedSigException("Registration Request JWT is invalid: "
                                                              + result.getViolationsAsString());
            }
        }
    } as Function<JwtValidatorResult, Void, ProcessDetachedSigException>
}

ApiClient apiClient() {
    def apiClientFapiContext = context.asContext(ApiClientFapiContext.class)
    def apiClientOpt = apiClientFapiContext.getApiClient()
    if (apiClientOpt.isEmpty()) {
        logger.error("apiClient must be identified before this script - it should exist in the ApiClientFapiContext")
        throw new IllegalStateException("Route is configured incorrectly, " + SCRIPT_NAME +
                                                "requires apiClient context attribute")
    }
    return apiClientOpt.get()
}

/**
 * Report a processing failure.
 * @param status HTTP status
 * @param message error message
 * @return Promise of a response
 */
Promise<Response, NeverThrowsException> fail(Status status, String message) {
    logger.error(SCRIPT_NAME + message)
    return errorResponseAsync(status, UNKNOWN.getCode(), message)
}

void validateArgs() {
    requireNonNull(clock)
    requireNonNull(routeArgHeaderName)
    requireNonNull(routeArgTrustedAnchor)
    requireNonNull(routeArgClockSkewAllowance)
}