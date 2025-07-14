import org.forgerock.openig.fapi.apiclient.ApiClientFapiContext
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import static org.forgerock.json.JsonValue.field
import static org.forgerock.openig.el.Bindings.bindings
import org.forgerock.openig.el.Bindings
import org.forgerock.openig.el.Expression
import org.forgerock.openig.fapi.apiclient.ApiClient

Optional<ApiClient> apiClientOpt = context.asContext(ApiClientFapiContext.class).getApiClient()
Bindings bindings = bindings(context)
Expression<String> trustStorePathExpr = Expression.valueOf(trustStorePathExprVal, String.class, bindings)
String trustStorePath = trustStorePathExpr.evaluateNow(bindings)
JsonValue debug = json(object(
        field("apiClient", apiClientOpt.orElse("empty")),
        //field("apiClient.jwkSet", apiClientOpt.map(apiClient -> apiClient.getJwkSetSecretStore().get()).orElse("empty")),
        field("truststore", trustStorePath)))
logger.debug("[JwkSetSecretStore.Log]: {}", debug)
next.handle(context, request)