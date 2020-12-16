import groovy.json.JsonOutput

/*
 * getAccountList
 *
 * Stub for account list from resource server
 * Return dummy data
 */

def getAccountList(username) {

    return [
      [
        "currency" : "GBP",
        "account" : [ [
                          "currency" : null,
                          "account" : null,
                          "identification" : "80200110203345",
                          "accountId" : null,
                          "schemeName" : "UK.OBIE.SortCodeAccountNumber",
                          "secondaryIdentification" : "00021",
                          "accountType" : null,
                          "accountSubType" : null,
                          "nickname" : null,
                          "name" : "Mr Kevin"
                      ] ],
        "identification" : null,
        "accountId" : "22289",
        "schemeName" : null,
        "secondaryIdentification" : null,
        "accountType" : "Personal",
        "accountSubType" : "CurrentAccount",
        "nickname" : "Bills",
        "name" : null
      ],
      [
        "currency" : "GBP",
        "account" : [ [
                          "currency" : null,
                          "account" : null,
                          "identification" : "80200110203348",
                          "accountId" : null,
                          "schemeName" : "UK.OBIE.SortCodeAccountNumber",
                          "secondaryIdentification" : null,
                          "accountType" : null,
                          "accountSubType" : null,
                          "nickname" : null,
                          "name" : "Mr Kevin"
                      ] ],
        "identification" : null,
        "accountId" : "31820",
        "schemeName" : null,
        "secondaryIdentification" : null,
        "accountType" : "Personal",
        "accountSubType" : "CurrentAccount",
        "nickname" : "Household",
        "name" : null
      ]
    ]
}

// Pull consent details from intent id embedded in consent request from AM

// TODO: Figure out why contexts expression doesn't work in route args

def consentRequest = contexts.jwtValidation.value
def intentId = contexts.jwtValidation.claims.claims.id_token.openbanking_intent_id.value.toString().replaceAll('"','')
def username = contexts.jwtValidation.claims.username.toString()
def clientName = contexts.jwtValidation.claims.client_name.toString()

def scopes = contexts.jwtValidation.claims.scopes
def scopeList = scopes.asMap().entrySet().toArray()


// Figure out whether this is an account info or payment request from the scope

def flow = ""

if (scopes.contains("accounts"))  {
    logger.debug("Detected AISP flow")
  flow = "aisp"
}
else if (scopes.contains("payments")) {
    logger.debug("Detected PISP flow")
    flow = "pisp"
}
else {
    logger.error("Error: cannot find flow from scopes")
    return new Response(Status.FORBIDDEN)
}

// Fetch the intent from IDM

Request intentRequest = new Request();
intentRequest.setMethod('GET');

def objName = (flow == "aisp") ? objAccountConsent : objPaymentConsent
intentRequest.setUri(idmBaseUri + "/openidm/managed/" + objName + "/" + intentId)

http.send(intentRequest).then(intentResponse -> {
    intentRequest.close()
    logger.debug("Back from IDM")

    def intentResponseStatus = intentResponse.getStatus();
    def intentResponseContent = intentResponse.getEntity();
    def intentResponseObject = intentResponseContent.getJson();
    Response response = new Response(Status.OK)

    // TODO: Integrity check - verify status and TPP details as expected

    if (flow == "aisp") {

        // Build a response with account information details

        logger.debug("AISP Flow")

        // Test UI has some issues with case, plus some misspelling of field names (e.g. AIPS)

        intentResponseObject.data = intentResponseObject.Data
        intentResponseObject.data.permissions = intentResponseObject.data.Permissions

        def responseObj = [
                "consentRequest"             : consentRequest,
                "consentRequestFieldName"    : "consent_request",
                "clientName"                 : clientName,
                "state"                      : null,
                "username"                   : username,
                "scopeList"                  : scopeList,
                "accountList"                : getAccountList(username),
                "claims"                     : ["id_token"],
                "initiationClaims"           : intentResponseObject.Data.Permissions,
                "obPaymentConsentPISP"       : null,
                "flow"                       : "aisp",
                "obAccountsAccessConsentAIPS": intentResponseObject,
                "errorDetails"               : null
        ]

        responseJson = JsonOutput.toJson(responseObj);

    }
    else {

        // Build a response with payment details

        logger.debug("PISP Flow")

        // Test UI has some issues with case - we can discard this once UI fixed

        intentResponseObject.data = intentResponseObject.Data
        intentResponseObject.data.initiation = intentResponseObject.data.Initiation
        intentResponseObject.data.initiation.debtorAccount = intentResponseObject.data.Initiation.debtorAccount

        intentResponseObject.data.initiation.instructedAmount = intentResponseObject.data.Initiation.InstructedAmount
        intentResponseObject.data.initiation.instructedAmount.amount = intentResponseObject.data.Initiation.InstructedAmount.Amount
        intentResponseObject.data.initiation.instructedAmount.currency = intentResponseObject.data.Initiation.InstructedAmount.Currency


        def responseObj = [
                "consentRequest"             : consentRequest,
                "consentRequestFieldName"    : "consent_request",
                "clientName"                 : "Demo TPP Dashboard",
                "state"                      : null,
                "username"                   : username,
                "scopeList"                  : scopeList,
                "accountList"                : getAccountList(username),
                "claims"                     : ["id_token"],
                "initiationClaims" : intentResponseObject.Data.Initiation,
                "obPaymentConsentPISP" : intentResponseObject,
                "flow" : "pisp",
                "obAccountsAccessConsentAIPS" : null,
                "errorDetails" : null
        ]

        responseJson = JsonOutput.toJson(responseObj);
    }

    logger.debug("Final JSON " + responseJson)
    response.setEntity(responseJson);
    return response

}).then(response -> { return response })
