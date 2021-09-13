import groovy.json.JsonOutput

/*
 * Handle consent response
 * Update account/payment intent status to authorise and add user/account details
 *
 * TODO: handle payment with debtor properly
 */

FLOW_AISP = "aisp"
FLOW_PISP = "pisp"

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

// TODO: Figure out why expression doesn't work in script args from route

def redirectUri = contexts.jwtValidation.claims.consentApprovalRedirectUri.asString()
def consentJwt = contexts.jwtBuilder.value
def requestObj = request.getEntity().getJson()
def intentId = contexts.jwtValidation.claims.claims.id_token.openbanking_intent_id.value.asString()
def user = contexts.jwtValidation.claims.username.asString()


/*
 * getDebtorAccount()
 *
 * Stub for calling resource server for account info
 * Return dummmy account data
 */

def getDebtorAccount(accountId) {
    return [
            "Identification": "80200110203345",
            "Name": "Smith"
    ]
}

/*
 * authorisePatchRequest
 *
 * Build patch request body for updating intent to authorised
 */

def authorisePatchRequest (intentId, account, user, flow) {

    def body = [
      [
        "operation":"replace",
        "field":"/Data/Status",
        "value":"Authorised"
      ],
      [
        "operation":"replace",
        "field":"/user",
        "value": [ "_ref": "managed/" + routeArgObjUser + "/" + user ]
      ],
      flow == FLOW_AISP ?
        [
              "operation":"replace",
              "field":"/accounts",
              "value": account
        ] :
        [
              "operation":"add",
              "field":"/Data/DebtorAccount",
              "value": getDebtorAccount(account)
        ]
    ]

    return body
}

// Integrity check

if (requestObj.decision != "allow") {
    message = "Bad decision " + requestObj.decision
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

if (requestObj.flow != FLOW_AISP && requestObj.flow != FLOW_PISP) {
    message = "Bad flow " + requestObj.flow
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// Update the account info or payment intent to authorised

logger.debug("Updating account intent " + intentId)

Request patchRequest = new Request();
patchRequest.setMethod('POST');
patchRequest.setUri(idmBaseUri + "/openidm/managed/" + (requestObj.flow == FLOW_AISP ? routeArgObjAccountAccessConsent : routeArgObjDomesticPaymentConsent) + "/" + intentId + "?_action=patch");
patchRequest.getHeaders().add("Content-Type","application/json");
patchRequest.setEntity(JsonOutput.toJson(authorisePatchRequest(intentId, requestObj.account, user, requestObj.flow)))

http.send(patchRequest).then(patchResponse -> {
  patchRequest.close()
  logger.debug("Back from IDM")
  def patchResponseContent = patchResponse.getEntity();
  def patchResponseStatus = patchResponse.getStatus();

  logger.debug("status " + patchResponseStatus);
  logger.debug("entity " + patchResponseContent);

  if (patchResponseStatus != Status.OK) {
      message = "Failed to patch consent"
      logger.error(message)
      response.status = patchResponseStatus
      response.entity = "{ \"error\":\"" + message + "\"}"
      return response
  }
  def responseObj = [
        "consentJwt": consentJwt,
        "requestMethod": null,
        "redirectUri": redirectUri
  ]
  Response response = new Response(Status.OK)
  response.setEntity(JsonOutput.toJson(responseObj));
  return response
}).then(response -> { return response })


