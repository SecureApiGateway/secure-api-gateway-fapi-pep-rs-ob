import groovy.json.JsonOutput
import org.forgerock.http.protocol.Status
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.secrets.Purpose
import org.forgerock.secrets.keys.SigningKey

/**
 * Sign each event from the request payload to be import through admin/data/events RS API as Signed JWT SET
 *
 * An Event Notification message needs to be structured as JWT
 * aligned with Security Event Token standard (SET) (https://datatracker.ietf.org/doc/html/rfc8417)
 *
 * Event Notifications messages must be signed for non-repudiation
 */
/*
POST Request example:
{
"tppId": "3ffb98cc-be98-4b10-a405-bde41e88c2c7",
"events":
  [
    {
      "iss": "https://examplebank.com/",
      "iat": 1516239022,
      "jti": "b460a07c-4962-43d1-85ee-9dc10fbb8f6c",
      "sub": "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003",
      "aud": "7umx5nTR33811QyQfi",
      "txn": "dfc51628-3479-4b81-ad60-210b43d02306",
      "toe": 1516239022,
      "events": {
        "urn:uk:org:openbanking:events:resource-update": {
          "subject": {
            "subject_type": "http://openbanking.org.uk/rid_http://openbanking.org.uk/rty",
            "http://openbanking.org.uk/rid": "pmt-7290-003",
            "http://openbanking.org.uk/rty": "domestic-payment",
            "http://openbanking.org.uk/rlk": [
              {
                "version": "v3.0",
                "link": "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003"
              },
              {
                "version": "v1.1",
                "link": "https://examplebank.com/api/open-banking/v1.1/payment-submissions/pmt-7290-003"
              }
            ]
          }
        }
      }
    }
  ]
}
Expected result by admin/data/events RS API to import the events
{
  "tppId": "3ffb98cc-be98-4b10-a405-bde41e88c2c7",
  "events": [
    {
      "jti": "b460a07c-4962-43d1-85ee-9dc10fbb8f6c",
      "set": "eyJ0eXAiOiJKV1QiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTY5MjM3MzAxNy4zNzksImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiY3JpdCI6WyJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvaXNzIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay90YW4iXSwia2lkIjoieGNKZVZ5dFRrRkwyMWxISVVWa0FkNlFWaTRNIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDQxUkVBQVkiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImI0NjBhMDdjLTQ5NjItNDNkMS04NWVlLTlkYzEwZmJiOGY2YyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZWJhbmsuY29tL2FwaS9vcGVuLWJhbmtpbmcvdjMuMC9waXNwL2RvbWVzdGljLXBheW1lbnRzL3BtdC03MjkwLTAwMyIsImF1ZCI6Ijd1bXg1blRSMzM4MTFReVFmaSIsInR4biI6ImRmYzUxNjI4LTM0NzktNGI4MS1hZDYwLTIxMGI0M2QwMjMwNiIsInRvZSI6MTUxNjIzOTAyMiwiZXZlbnRzIjp7InVybjp1azpvcmc6b3BlbmJhbmtpbmc6ZXZlbnRzOnJlc291cmNlLXVwZGF0ZSI6eyJzdWJqZWN0Ijp7InN1YmplY3RfdHlwZSI6Imh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcmlkX2h0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcnR5IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9yaWQiOiJwbXQtNzI5MC0wMDMiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3J0eSI6ImRvbWVzdGljLXBheW1lbnQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3JsayI6W3sidmVyc2lvbiI6InYzLjAiLCJsaW5rIjoiaHR0cHM6Ly9leGFtcGxlYmFuay5jb20vYXBpL29wZW4tYmFua2luZy92My4wL3Bpc3AvZG9tZXN0aWMtcGF5bWVudHMvcG10LTcyOTAtMDAzIn0seyJ2ZXJzaW9uIjoidjEuMSIsImxpbmsiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS9hcGkvb3Blbi1iYW5raW5nL3YxLjEvcGF5bWVudC1zdWJtaXNzaW9ucy9wbXQtNzI5MC0wMDMifV19fX19.MNhxg1ujcn0y-NW7DrSRw-HUaRqO28ifX7lHSxW_xcnupo9tMsP2Z0hkLIRquRa1gRE--WLWc_E7prUmsUYUqr4MTcX1XQgAYs3FHW5mX6x5wLrP7zC4Hs5SKqjPiEPqov27ZlBTpbXRRXe5L8COCRPEr7AGyP0QvOQ1xOUxWd1PVLaJHVi7RNI2V--YJAAopwSu_oIadE1CBPxuqiyVmXqeQUXG-q9O6nkjF_2SusBTz_EBh91wRIanZa47Hcwj1zb4DDWOu0nY5E3zFq98iWkTvChnMn1EHKLn-fBMT9X7thbK5g3q4iduJCprRJCLZnLYqHIy03XcgcwR3vZgpA"
    },
    {
      "jti": "b460a07c-4962-43d1-85ee-9dc10fbb8f7c",
      "set": "eyJ0eXAiOiJKV1QiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTY5MjM3MzAxNy4zNzUsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiY3JpdCI6WyJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvaXNzIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay90YW4iXSwia2lkIjoieGNKZVZ5dFRrRkwyMWxISVVWa0FkNlFWaTRNIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDQxUkVBQVkiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImI0NjBhMDdjLTQ5NjItNDNkMS04NWVlLTlkYzEwZmJiOGY2YyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZWJhbmsuY29tL2FwaS9vcGVuLWJhbmtpbmcvdjMuMC9waXNwL2RvbWVzdGljLXBheW1lbnRzL3BtdC03MjkwLTAwMyIsImF1ZCI6Ijd1bXg1blRSMzM4MTFReVFmaSIsInR4biI6ImRmYzUxNjI4LTM0NzktNGI4MS1hZDYwLTIxMGI0M2QwMjMwNiIsInRvZSI6MTUxNjIzOTAyMiwiZXZlbnRzIjp7InVybjp1azpvcmc6b3BlbmJhbmtpbmc6ZXZlbnRzOnJlc291cmNlLXVwZGF0ZSI6eyJzdWJqZWN0Ijp7InN1YmplY3RfdHlwZSI6Imh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcmlkX2h0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcnR5IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9yaWQiOiJwbXQtNzI5MC0wMDMiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3J0eSI6ImRvbWVzdGljLXBheW1lbnQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3JsayI6W3sidmVyc2lvbiI6InYzLjAiLCJsaW5rIjoiaHR0cHM6Ly9leGFtcGxlYmFuay5jb20vYXBpL29wZW4tYmFua2luZy92My4wL3Bpc3AvZG9tZXN0aWMtcGF5bWVudHMvcG10LTcyOTAtMDAzIn0seyJ2ZXJzaW9uIjoidjEuMSIsImxpbmsiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS9hcGkvb3Blbi1iYW5raW5nL3YxLjEvcGF5bWVudC1zdWJtaXNzaW9ucy9wbXQtNzI5MC0wMDMifV19fX19.nf4oYEg6OINDEwHBDtdo_62YMWYckybRsv7vnzKLfJpNqm-bI02An7sOZSfhcJrs-nURv_Fo3_wydLal1pXEwgwhUe4-5IvtdqHfYnbzTv9XHXSNtiJIvvT6XzrPtRPyc79G7M_zSd3GMlTOkmKTeOu7F12SylHWXpff0MMu45A2NvcUat6BIqA09KFs9_3dLA9eX4Ng26oBIRYJqe8owKm2m-hvIN6SWBAUiFxIzmXfpM7GPo3tU2zc8NErDydvZt6TfDKDvbWGQiawO4XEdLRDg0YsTZv-N6bv99lDEvv1nqO-xKTaH_G9JSKLrf9KH7ou1cmli1wDh28bE2Fi9Q"
    },
    {
      "jti": "b460a07c-4962-43d1-85ee-9dc10fbb8f8c",
      "set": "eyJ0eXAiOiJKV1QiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTY5MjM3MzAxNy4zNzEsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiY3JpdCI6WyJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvaXNzIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay90YW4iXSwia2lkIjoieGNKZVZ5dFRrRkwyMWxISVVWa0FkNlFWaTRNIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDQxUkVBQVkiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImI0NjBhMDdjLTQ5NjItNDNkMS04NWVlLTlkYzEwZmJiOGY2YyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZWJhbmsuY29tL2FwaS9vcGVuLWJhbmtpbmcvdjMuMC9waXNwL2RvbWVzdGljLXBheW1lbnRzL3BtdC03MjkwLTAwMyIsImF1ZCI6Ijd1bXg1blRSMzM4MTFReVFmaSIsInR4biI6ImRmYzUxNjI4LTM0NzktNGI4MS1hZDYwLTIxMGI0M2QwMjMwNiIsInRvZSI6MTUxNjIzOTAyMiwiZXZlbnRzIjp7InVybjp1azpvcmc6b3BlbmJhbmtpbmc6ZXZlbnRzOnJlc291cmNlLXVwZGF0ZSI6eyJzdWJqZWN0Ijp7InN1YmplY3RfdHlwZSI6Imh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcmlkX2h0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvcnR5IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9yaWQiOiJwbXQtNzI5MC0wMDMiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3J0eSI6ImRvbWVzdGljLXBheW1lbnQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL3JsayI6W3sidmVyc2lvbiI6InYzLjAiLCJsaW5rIjoiaHR0cHM6Ly9leGFtcGxlYmFuay5jb20vYXBpL29wZW4tYmFua2luZy92My4wL3Bpc3AvZG9tZXN0aWMtcGF5bWVudHMvcG10LTcyOTAtMDAzIn0seyJ2ZXJzaW9uIjoidjEuMSIsImxpbmsiOiJodHRwczovL2V4YW1wbGViYW5rLmNvbS9hcGkvb3Blbi1iYW5raW5nL3YxLjEvcGF5bWVudC1zdWJtaXNzaW9ucy9wbXQtNzI5MC0wMDMifV19fX19.aBHux5ZFFXBYesmADufysJKTtLdz2NPHhnGjGoyEMKo1gQs9Y7rc2J3fZREZuYyQXHdPWjcwtx_qFbWPNnWQLKZDZAstMyOOGrGvaUeFl1Tv9Q0Tepc7tozCKxAngnTRPvGtRgmsQRjJx-Xb6rWnIhQwfBOpmzz89F84lGbr2QuosG8Y9PM0vBS-1oYuxnob9EhIbsVhQDOteF5PwIDdGHDxrJiILQ-l5bATX2tIO4KngplUHl1ee8OejlqKVH1T_nD0IgNTtvKSR85tV3XCRtivxJowp8HzDzvy0jnIDt2nNMYKEfY08fT3IvoyzKl5PgWEHFLPc9xziCtZqel6Ow"
    }
  ]
}

Validate signature
- You can validate the signature of the SET (JWT) in: https://jwt.davetonge.co.uk/
- Copy a 'set' value and paste in the web page.
- JWKs URL endpoint: https://keystore.openbankingtest.org.uk/0015800001041REAAY/0015800001041REAAY.jwks
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[SignEventNotifications] (" + fapiInteractionId + ") - "

// we signing the messages only if is a POST or PUT request (import, update)
if(request.method == "POST" || request.method == "PUT") {
    IAT_CRIT_CLAIM = "http://openbanking.org.uk/iat"
    ISS_CRIT_CLAIM = "http://openbanking.org.uk/iss"
    TAN_CRIT_CLAIM = "http://openbanking.org.uk/tan"

    def eventsRequest = request.entity.getJson()

    def apiClientId = eventsRequest.apiClientId

    def events = eventsRequest.events

    logger.debug(SCRIPT_NAME + "Running...")
    logger.debug(SCRIPT_NAME + "routeArgSecretId: " + routeArgSecretId)
    logger.debug(SCRIPT_NAME + "routeArgKid: " + routeArgKid)

    JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(routeArgAlgorithm)
    logger.debug(SCRIPT_NAME + "Algorithm initialised: " + signAlgorithm)

    Purpose<SigningKey> purpose = new JsonValue(routeArgSecretId).as(purposeOf(SigningKey.class))

    SigningManager signingManager = new SigningManager(routeArgSecretsProvider)

    List<String> critClaims = new ArrayList<String>();
    critClaims.add(IAT_CRIT_CLAIM);
    critClaims.add(ISS_CRIT_CLAIM);
    critClaims.add(TAN_CRIT_CLAIM);

    def newApiClientEvent = [
            "apiClientId" : apiClientId,
            "events": []
    ]

// response object
    response = new Response(Status.OK)
    response.headers['Content-Type'] = "application/json"

// check if events have been provided in the request
    if (events == null || events.isEmpty()) {
        message = "No events to import found"
        logger.error(SCRIPT_NAME + message)
        response.status = Status.INTERNAL_SERVER_ERROR
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    signingManager.newSigningHandler(purpose).then({ signingHandler ->
        events.forEach(event -> {
            JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(event)
            logger.debug(SCRIPT_NAME + "jwtClaimSet: {}", jwtClaimsSet)
            String jwt
            logger.debug(SCRIPT_NAME + "JWT SET building...")
            try {
                jwt = new JwtBuilderFactory()
                        .jws(signingHandler)
                        .headers()
                        .alg(signAlgorithm)
                        .kid(routeArgKid)
                        .header(IAT_CRIT_CLAIM, System.currentTimeMillis() / 1000)
                        .header(ISS_CRIT_CLAIM, obAspspOrgId) // For an ASPSP the ISS_CRIT_CLAIM is the OB Issued orgId
                        .header(TAN_CRIT_CLAIM, routeArgTrustedAnchor)
                        .crit(critClaims)
                        .done()
                        .claims(jwtClaimsSet)
                        .build()
            } catch (java.lang.Exception e) {
                logger.debug(SCRIPT_NAME + "Error building JWT SET: " + e)
            }

            if (jwt == null || jwt.length() == 0) {
                message = "Error creating signature JWT SET"
                logger.error(SCRIPT_NAME + message)
                response.status = Status.INTERNAL_SERVER_ERROR
                response.entity = "{ \"error\":\"" + message + "\"}"
                return response
            }
            var newEvent = [
                    "jti": event.jti,
                    "set": jwt
            ]

            for (def ev : newApiClientEvent.events) {
                if (ev.jti == newEvent.jti) {
                    message = "Error importing events, property 'jti' [" + ev.jti + "] duplicated and must be unique."
                    logger.error(SCRIPT_NAME + message)
                    response.status = Status.INTERNAL_SERVER_ERROR
                    response.entity = "{ \"error\":\"" + message + "\"}"
                    return response
                }
            }
            logger.debug(SCRIPT_NAME + "SET {}", newEvent)
            newApiClientEvent.events.push(newEvent)
        })
    })

    if (response.status.isSuccessful()) {
        logger.debug(SCRIPT_NAME + "SETs new request entity: {}", newApiClientEvent)
        Request newRequest = new Request(request)
        newRequest.entity = JsonOutput.toJson(newApiClientEvent)
        next.handle(context, newRequest)
    } else {
        return response
    }

} else {
    next.handle(context, request)
}