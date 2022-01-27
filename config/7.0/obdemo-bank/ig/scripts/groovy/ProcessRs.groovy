import org.forgerock.http.protocol.*

next.handle(context, request).thenOnResult(response -> {
    response.entity = response.entity.getString().replace('http://rs', 'https://' + request.getHeaders().getFirst('Host') + '/rs');

    //Replace the open banking domain with the IG domain
    response.entity = response.entity.getString().replace(request.getHeaders().getFirst('X-Host'), request.getHeaders().getFirst('X-Forwarded-Host') + "/rs");

    try {
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
        JsonValue newEntity = response.entity.getJson();
        newEntity.get("Data").remove("AccountAndTransactionAPI");
        newEntity.get("Data").add("AccountAndTransactionAPI", accountAndTransactionApi);

        response.entity = newEntity;
    }
    catch (Exception e) {
        logger.error("The response entity doesn't have the expected format")
    }

    return response;
});