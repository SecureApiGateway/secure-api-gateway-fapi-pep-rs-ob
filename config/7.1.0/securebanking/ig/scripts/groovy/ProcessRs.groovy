import org.forgerock.http.protocol.*


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ProcessRs] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request).thenOnResult(response -> {
    try {
        JsonValue newEntity = response.entity.getJson();

        //Account and Transaction
        List accountAndTransactionApi = response.entity.getJson().get("Data").get("AccountAndTransactionAPI").asList()
        for (JsonValue value : accountAndTransactionApi) {
            //Account Access Consents
            value.Links.links.add("CreateAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents");
            value.Links.links.add("GetAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.links.add("DeleteAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/aisp/account-access-consents/{ConsentId}");
        }

        //Payment Initiation
        List paymentInitiationAPI = response.entity.getJson().get("Data").get("PaymentInitiationAPI").asList()
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

            //Domestic Standing Order Consents
            value.Links.links.add("CreateDomesticStandingOrderConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-standing-order-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-standing-order-consents");
            value.Links.links.add("GetDomesticStandingOrderConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-standing-order-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-standing-order-consents/{ConsentId}");

            //International Payments Consents
            value.Links.links.add("CreateInternationalPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents");
            value.Links.links.add("GetInternationalPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents/{ConsentId}");
            value.Links.links.add("GetInternationalPaymentConsentsConsentIdFundsConfirmation", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents/{ConsentId}/funds-confirmation");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-payment-consents/{ConsentId}/funds-confirmation");

            //International Scheduled Payments Consents
            value.Links.links.add("CreateInternationalScheduledPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents");
            value.Links.links.add("GetInternationalScheduledPaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents/{ConsentId}");
            value.Links.links.add("GetInternationalScheduledPaymentConsentsConsentIdFundsConfirmation", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents/{ConsentId}/funds-confirmation");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-scheduled-payment-consents/{ConsentId}/funds-confirmation");

            //International Standing Order Consents
            value.Links.links.add("CreateInternationalStandingOrderConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-standing-order-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-standing-order-consents");
            value.Links.links.add("GetInternationalStandingOrderConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-standing-order-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/international-standing-order-consents/{ConsentId}");

            //File payments Consents
            value.Links.links.add("CreateFilePaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents");
            value.Links.links.add("CreateFilePaymentFile", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}/file");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}/file");
            value.Links.links.add("GetFilePaymentConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}");
            value.Links.links.add("GetFilePaymentFile", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}/file");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/file-payment-consents/{ConsentId}/file");

            //Domestic VRP Payment Consents
            value.Links.links.add("CreateDomesticVRPConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents");
            value.Links.links.add("GetDomesticVRPConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents/{ConsentId}");
            value.Links.links.add("DeleteDomesticVRPConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents/{ConsentId}");
            value.Links.linkValues.add("https://" + request.getHeaders().getFirst('X-Forwarded-Host') + "/rs/open-banking/" + value.Version.asString() + "/pisp/domestic-vrp-consents/{ConsentId}");
        }

        response.entity = newEntity;
    }
    catch (Exception e) {
        logger.error(SCRIPT_NAME + "The response entity doesn't have the expected format", e)
    }

    return response;
});
