FROM google/cloud-sdk:alpine

ENV APP_FILE psd-2-rsc-sevice-0.0.2-SNAPSHOT.war
ENV APP_HOME /usr/apps/

EXPOSE 8083

WORKDIR $APP_HOME

RUN apk --update add openjdk8-jre

RUN gsutil cp gs://securebanking-public/$APP_FILE .

ENTRYPOINT ["sh", "-c"]
CMD ["exec java -Xms256M -Xmx512M -jar $APP_FILE"]