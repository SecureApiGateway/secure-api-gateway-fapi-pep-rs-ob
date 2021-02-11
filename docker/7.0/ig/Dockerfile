FROM gcr.io/forgerock-io/ig/pit1:7.0.1

# Copy all config files into the docker image.
# The default ig directory is /var/ig, and it expects subfolders config/ and scripts/ (if required)
COPY --chown=forgerock:root . /var/ig
COPY --chown=forgerock:root lib /opt/ig/lib
