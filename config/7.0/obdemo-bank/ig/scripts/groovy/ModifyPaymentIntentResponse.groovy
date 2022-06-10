SCRIPT_NAME = "[ModifyPaymentIntentResponse] - "
logger.debug(SCRIPT_NAME + " Running...")


next.handle(context, request).thenOnResult({ response ->
    def responseBody = response.getEntity().getJson();

    if (responseBody) {
        try{
            responseBody.get("Data").get("Initiation").get("DebtorAccount").remove("AccountId")
        }
        catch(Exception e)
        {
            logger.debug(SCRIPT_NAME + "Debtor Account's accountId is not set: " + responseBody)
        }

        logger.debug(SCRIPT_NAME + "The payment intent without Debtor Account's accountId: " + responseBody)
        response.setEntity(responseBody)
    }
})
