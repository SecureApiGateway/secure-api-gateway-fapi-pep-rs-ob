SCRIPT_NAME = "[SettingNewEntity] - "
logger.debug(SCRIPT_NAME + "Running...")

def newEntity = request.getEntity().getString().replace('grant_type=client_credentials','grant_type=password&username=' + userId + '&password=' + java.net.URLEncoder.encode(password, 'UTF-8'))
logger.debug(SCRIPT_NAME + "Setting entity to [{}]", newEntity)
request.setEntity(newEntity)

return http.send(context, request)