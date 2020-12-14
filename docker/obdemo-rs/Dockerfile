FROM google/cloud-sdk:alpine

ENV APP_FILE ForgerockREST-0.0.1-SNAPSHOT.jar
ENV APP_HOME /usr/apps/

EXPOSE 8089

WORKDIR $APP_HOME

RUN apk --update add openjdk8-jre

RUN gsutil cp gs://securebanking-public/$APP_FILE .

RUN ls -al $APP_HOME

ENTRYPOINT ["sh", "-c"]
CMD ["exec java -Xms256M -Xmx512M -Dserver.port=8089 -jar $APP_FILE"]
