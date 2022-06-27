/**
 * Gets the intent id from the access token claims and saves it on the attributes context
 */
import org.forgerock.http.protocol.*
import org.forgerock.http.util.Json

SCRIPT_NAME = "[SaveIntentIdOnAttributesContext] - "
logger.debug(SCRIPT_NAME + "Running...")

def intentId = JsonValue.json(Json.readJson(contexts.oauth2.accessToken.info.claims)).get("id_token").get("openbanking_intent_id").get("value").asString()
logger.error(SCRIPT_NAME + "Intent Id value: " + intentId)
attributes.put('openbanking_intent_id', intentId)

next.handle(context, request)