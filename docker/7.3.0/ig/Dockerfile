FROM gcr.io/forgerock-io/ig:2023.4.0
# Switching back to forgerock user, app will run as this
USER forgerock
# Create dir where secrets can be mounted into
RUN mkdir /var/ig/secrets
COPY --chown=forgerock:root bin/import-pem-certs.sh /home/forgerock
COPY --chown=forgerock:root lib /opt/ig/lib
# Check that the IG jar exists before continuing
RUN test -f /opt/ig/lib/secure-api-gateway-ig-extensions-*.jar

# Copy all config files into the docker image.
# The default ig directory is /var/ig, and it expects subfolders config/ and scripts/ (if required)
COPY --chown=forgerock:root audit-schemas /var/ig/audit-schemas/
COPY --chown=forgerock:root scripts /var/ig/scripts/
COPY --chown=forgerock:root config /var/ig/config/
