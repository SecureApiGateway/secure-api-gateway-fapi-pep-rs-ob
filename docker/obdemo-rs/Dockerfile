FROM openjdk:8-jre-alpine

ENV APP_FILE ForgerockREST-0.0.1-SNAPSHOT.jar
ENV APP_HOME usr/apps

EXPOSE 8089

ADD https://console.cloud.google.com/storage/browser/securebanking-public/$APP_FILE $APP_HOME/

WORKDIR $APP_HOME
ENTRYPOINT ["sh", "-c"]
CMD ["exec java -Xms256M -Xmx512M -Dserver.port=8089 -jar $APP_FILE"]
