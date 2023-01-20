#!/usr/bin/env bash
# This script copies the default cacerts to $TRUSTSTORE_PATH
# and imports all the certs contained in the $IG_PEM_TRUSTSTORE if it exists
#
# Copyright 2023 ForgeRock AS. All Rights Reserved
#

set -e
set -o pipefail

IG_DEFAULT_TRUSTSTORE=${IG_DEFAULT_TRUSTSTORE:-$JAVA_HOME/lib/security/cacerts}
# If a $IG_PEM_TRUSTSTORE is provided, import it into the truststore. Otherwise, do nothing
if [ -f "$IG_DEFAULT_TRUSTSTORE" ] && [ -f "$IG_PEM_TRUSTSTORE" ]; then
    TRUSTSTORE_PATH="${TRUSTSTORE_PATH:-/home/forgerock/igtruststore}"
    TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-changeit}"
    echo "Copying ${IG_DEFAULT_TRUSTSTORE} to ${TRUSTSTORE_PATH}"
    cp ${IG_DEFAULT_TRUSTSTORE} ${TRUSTSTORE_PATH}
    # Calculate the number of certs in the PEM file
    CERTS=$(grep 'END CERTIFICATE' $IG_PEM_TRUSTSTORE| wc -l)
    echo "Found (${CERTS}) certificates in $IG_PEM_TRUSTSTORE"
    echo "Importing (${CERTS}) certificates into ${TRUSTSTORE_PATH}"
    # For every cert in the PEM file, extract it and import into the JKS truststore
    for N in $(seq 0 $(($CERTS - 1))); do
        ALIAS="imported-certs-$N"
        cat $IG_PEM_TRUSTSTORE |
            awk "n==$N { print }; /END CERTIFICATE/ { n++ }" |
            keytool -noprompt -importcert -trustcacerts -storetype PKCS12 \
                    -alias "${ALIAS}" -keystore "${TRUSTSTORE_PATH}" \
                    -storepass "${TRUSTSTORE_PASSWORD}"
    done
    echo "Import complete!"
else
    echo "Nothing was imported to the truststore. Check ENVs IG_DEFAULT_TRUSTSTORE and IG_PEM_TRUSTSTORE"
    exit -1
fi
