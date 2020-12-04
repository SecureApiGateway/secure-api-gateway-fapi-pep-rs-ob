# ForgeRock DevOps and Cloud Deployment - Open Banking Accelerator Demo

This repository contains a demonstration deployment of the ForgeRock platform along with the ForgeRock Open Banking Accelerators. These accelerators are a set of plugins and configuration for meeting the UK Open Banking requirements, based on the [PSD2 Accelerator assets](https://github.com/ForgeRock/PSD2-Accelerators/tree/OpenBankingAccelerators).

The deployment is based on the [ForgeRock Cloud Developer Kit (CDK)](https://backstage.forgerock.com/docs/forgeops/7/index-forgeops.html) kubernetes deployment model

## Quick Start

```bash
# Create namespaces
kubectl create namespace obdemo-iam
kubectl create namespace obdemo-bank

# Initialise config
bin/config.sh init --profile obdemo-iam --version 7.0
bin/config.sh init --profile obdemo-bank --version 7.0

# DNS
sudo echo $(minikube ip) default.iam.example.com >> /etc/hosts
sudo echo $(minikube ip) default.bank.example.com >> /etc/hosts

# Start up 
skaffold run -p obdemo-iam
skaffold run -p obdemo-bank
```

## ForgeOps Deltas

This deployment is based on the ForgeOps Cloud Developer Kit, with the following modifications and additions:

- There is a new kustomize overlay at `kustomize/overlay/7.0/obdemo-iam`. The default `skaffold.yaml` file has a profile `obdemo-iam` pointing to this overlay.
- There is a new kustomize overlay at `kustomize/overlay/7.0/obdemo-bank`. The default `skaffold.yaml` file has a profile `obdemo-bank` pointing to this overlay.
- There is an additional deployment for the AM remote consent service front end (`docker/obdemo-rcs-ui`).
- There is an additional deployment for the AM remote consent service back end (`docker/obdemo-rcs-api`).
- There is an additional deployment for a demo resource server providing a mock bank API (`docker/obdemo-rs`).
- The IG deployment (`docker/7.0/ig`) has been modified to include a jar file with custom filters.
- The AM deployment (`docker/7.0/am`) has been modified to include a jar file with a custom scope validator.
- The configuration script `bin/config.sh` has been updated to handle amster export of dynamic configuration for subrealms.
- The ldif-importer task (`docker/7.0/ldif-importer`) has been updated with a modified `external-am-datastore.ldif` file to support dynamic configuration of subrealms.
- The AM Dockerfile has been updated to reduce the JVM memory allocation to 50% of container memory
- The IG configuration has been updated to increase the vertx max client header size to 16k

## Postman Collection

This repository includes a [Postman Collection](postman) for testing the deployment. Required steps for testing are as follows

- Enrol for an account at the [OBRI Directory](https://directory.ob.forgerock.financial)
- From the Directory dashboard, create a new software statement, and download the transport certificate and private key
- Configure Postman to use this client certificate and key for the hosts `default.iam.example.com`, `default.bank.example.com`, `jwkms.ob.forgerock.financial` and `matls.service.directory.ob.forgerock.financial`

If you changed the FQDN value for the deployment, change the FQDN variable in the provided Postman environment, and define this host for client certificates as above.


## Disclaimer

>These samples are provided on an “as is” basis, without warranty of any kind, to the fullest extent
permitted by law. ForgeRock does not warrant or guarantee the individual success developers
may have in implementing the code on their development platforms or in
production configurations. ForgeRock does not warrant, guarantee or make any representations
regarding the use, results of use, accuracy, timeliness or completeness of any data or
information relating to these samples. ForgeRock disclaims all warranties, expressed or implied, and
in particular, disclaims all warranties of merchantability, and warranties related to the code, or any
service or software related thereto. ForgeRock shall not be liable for any direct, indirect or
consequential damages or costs of any type arising out of any action taken by you or others related
to the samples.

