import org.forgerock.http.protocol.*

SCRIPT_NAME = "[ProcessRs] - "
logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request).thenOnResult(response -> {
    response.entity = response.entity.getString().replace('http://rs', 'https://' + request.getHeaders().getFirst('Host') + '/rs');

    //Replace the open banking domain with the IG domain
    response.entity = response.entity.getString().replace(request.getHeaders().getFirst('X-Host'), request.getHeaders().getFirst('X-Forwarded-Host') + "/rs");

    try {
        JsonValue newEntity = response.entity.getJson();

        //Account and Transaction
        JsonValue accountAndTransactionApi = response.entity.getJson().get("Data").get("AccountAndTransactionAPI");
        for (JsonValue value : accountAndTransactionApi) {
            //Account Access Consents
            value.Links.links.add("CreateAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents");
            value.Links.links.add("GetAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.links.add("DeleteAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
        }
        newEntity.get("Data").remove("AccountAndTransactionAPI");
        newEntity.get("Data").add("AccountAndTransactionAPI", accountAndTransactionApi);

        //Payment Initiation
        JsonValue paymentInitiationAPI = response.entity.getJson().get("Data").get("PaymentInitiationAPI");
        for (JsonValue value : paymentInitiationAPI) {
            //Domestic Payments Consents
            value.Links.links.add("CreateDomesticPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents");
            value.Links.links.add("GetDomesticPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents/{ConsentId}");
            value.Links.links.add("GetDomesticPaymentConsentsConsentIdFundsConfirmation", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents/{ConsentId}/funds-confirmation");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-payment-consents/{ConsentId}/funds-confirmation");

            //Domestic Scheduled Payments Consents
            value.Links.links.add("CreateDomesticScheduledPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-scheduled-payment-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-scheduled-payment-consents");
            value.Links.links.add("GetDomesticScheduledPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-scheduled-payment-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-scheduled-payment-consents/{ConsentId}");
        }
        newEntity.get("Data").remove("paymentInitiationAPI");
        newEntity.get("Data").add("paymentInitiationAPI", paymentInitiationAPI);

        response.entity = newEntity;
    }
    catch (Exception e) {
        logger.error(SCRIPT_NAME + "The response entity doesn't have the expected format")
    }

    return response;
});