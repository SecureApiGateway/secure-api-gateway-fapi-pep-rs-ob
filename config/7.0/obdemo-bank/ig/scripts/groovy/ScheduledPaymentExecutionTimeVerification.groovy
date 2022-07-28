import org.joda.time.DateTime;


SCRIPT_NAME = "[ScheduledPaymentExecutionTimeVerification] - "
logger.debug(SCRIPT_NAME + "Running...")

def method = request.method
if (method != "POST") {
    //This script should be executed only if it is a POST request
    logger.debug(SCRIPT_NAME + "Skipping the filter because the method is not POST, the method is " + method)
    return next.handle(context, request)
}

def requestObj = request.entity.getJson()

def requestedExecutionDateTime = ""
try {
    requestedExecutionDateTime = requestObj.Data.Initiation.RequestedExecutionDateTime
} catch (java.lang.Exception e) {
    logger.error(SCRIPT_NAME + "Could not obtain requestedExecutionDateTime value from request: " + e)
}

logger.debug(SCRIPT_NAME + "Requested requestedExecutionDateTime: " + requestedExecutionDateTime)
if (requestedExecutionDateTime) {
    DateTime paymentExecutionDateTime = new DateTime(requestedExecutionDateTime);

    if (paymentExecutionDateTime.afterNow) {
        logger.debug("requestedExecutionDateTime validated successfully.")
        return next.handle(context, request)
    }
}

logger.debug(SCRIPT_NAME + "RequestedExecutionDateTime is invalid: " + requestedExecutionDateTime + ". Current Time is: " + new DateTime())

message = "Invalid RequestedExecutionDateTime value in the request payload."
logger.error(SCRIPT_NAME + message)
response = new Response(Status.BAD_REQUEST)
response.headers['Content-Type'] = "application/json"
response.status = Status.BAD_REQUEST
response.entity = "{ \"error\":\"" + message + "\"}"
return response

