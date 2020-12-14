# ForgeRock DevOps and Cloud Deployment - Open Banking Accelerator Demo

This repository contains a demonstration deployment of the ForgeRock platform along with the ForgeRock Open Banking Accelerators. These accelerators are a set of plugins and configuration for meeting the UK Open Banking requirements, based on the [PSD2 Accelerator assets](https://github.com/ForgeRock/PSD2-Accelerators/tree/OpenBankingAccelerators).

## Read first (Environment Setup)
- [DevOps Developer's Guide](https://backstage.forgerock.com/docs/forgeops/7/index-forgeops.html)

## Principal Folder structure

| type | folder |
|--- | ---|
| profile master | `config/7.0/obdemo-bank/` |
| component | `${profile master}/ig` |
| environment | `${component}/config/${environment}` |
| shared configuration folder | `${component}/lib` |
| shared configuration folder | `${component}/routes` |
| shared configuration folder | `${component}/scripts` |
> The `shared configuration folder` are configurations shared through all environments to avoid the duplications.
> All environments will use the same lib, routes and scripts.

| type | folder |
|---|---|
| staging area | `docker/7.0/` |
| component | `${staging area}/ig` |

| type | folder |
| --- | --- |
| overlay | `kustomize/overlay/7.0/obdemo-bank` |
| environment | `${overlay}/${environment}` |

## Quick Start
To make more easy the deployment for developers there is a config script to initialise the IG docker with the below arguments.
- IG Environment argument: allow deploy any IG environment created on `configuration profile master` `config/7.0/obdemo-bank/ig/config/${environment}`
  - config/7.0/obdemo-bank/ig/config/dev (default)
  - config/7.0/obdemo-bank/ig/config/prod
- IG mode argument:
    - development (default): this mode make able the IG UI and Studio.
    - production: no IG UI and Studio.
> The initialisation default will initialise all `IG` component with defaults values `dev environment` and `development mode`.
> The `lib`, `routes`, `scripts` folders are shared between the environments.
```bash
# Initialise config with defaults
bin/config.sh init

**************************************************************************************
Initialisation of IG 'docker/7.0/ig-local' for [dev] environment in [development] mode
**************************************************************************************
....
....
```
```bash
# Initialise config with arguments
bin/config.sh init --env prod --igmode production

**************************************************************************************
Initialisation of IG 'docker/7.0/ig-local' for [prod] environment in [production] mode
**************************************************************************************
....
....
```
```bash
# DNS
sudo echo $(minikube ip) default.bank.example.com >> /etc/hosts
```
```bash
# Start up default 'dev' profile 
skaffold run 
```
```bash
# Start up `prod` profile
skaffold run -p prod
```
## IG UI Development mode
- https://**${FQDN}**/ig/openig/studio/

## Create a new environment
See [Principal Folder structure section](#principal-folder-structure)
1. Create a new folder on `profile master` `${component}/config/` with the name of your environment.
   ```bash
   mkdir config/7.0/obdemo-bank/ig/config/my-environment
   ```
1. Create the config folder on your `new-enviroment`
   ```bash
   mkdir config/7.0/obdemo-bank/ig/config/my-environment/config
   ```
1. Add the configuration descriptor files for the `IG` component (you can copy them from other env):
    - admin.json
    - config.json
    - logback.xml
1. Add the environment to kustomization
   1. `mkdir kustomize/overlay/7.0/obdemo-bank/my-environment`
   1. Copy the kustomization from another environment to `my-environment`
      1. Configmap.yaml
      1. ingress-path.yaml
      1. kustomization.yaml
1. Add the profile to `skaffold` in the section `profiles`
   ```yaml
    - name: my-env-profile
      build:
        artifacts: *default-artifacts
        tagPolicy:
          sha256: {}
      deploy:
        statusCheckDeadlineSeconds: 600
        kustomize:
          path: ./kustomize/overlay/7.0/obdemo-bank/my-environment
   ```
1. Prepare stage area
    ```bash
    bin/config.sh --env my-environment --igmode development
    ****************************************************************************************
    Initialisation of 'docker/7.0/ig' for [my-environment] environment in [development] mode
    ****************************************************************************************
    ```
1. Run skaffold deployment
    ```bash
    skaffold run -p my-env-profile
    ```
1. Clean skaffold deployment
    ```bash
    skaffold delete -p my-env-profile
    ```
1. Clean stage area
    ```bash
    bin/config.sh clean
    ```
## ForgeOps Deltas

This deployment is based on the ForgeOps Cloud Developer Kit, with the following modifications and additions:

- The config initialisation script have new arguments `--env ${environment}` and `--igmode ${igmode}`
- There is a new kustomize overlay at `kustomize/overlay/7.0/obdemo-bank/${environment}`. The default `skaffold.yaml` file uses this overlay by default
  - New environment `dev`
  - New environment `prod`
- There is an additional deployment for the AM remote consent service front end (`docker/obdemo-rcs-ui`).
- There is an additional deployment for the AM remote consent service back end (`docker/obdemo-rcs-api`).
- There is an additional deployment for a demo resource server providing a mock bank API (`docker/obdemo-rs`).
- The IG deployment (`docker/7.0/ig`) has been modified to include a jar file with custom filters.
- The IG configuration has been updated to increase the vertx max client header size to 16k.
- New feature to add new custom environments, see [Create a new environment](#create-a-new-environment).

## Postman Collection

This repository includes a [Postman Collection](postman) for configuring the FIDC tenant and testing the deployment. 
> Follow the instructions on [postman section](postman/readme.md) to prepare the postman client environment.

Required steps for testing are as follows

- Enrol for an account at the [OBRI Directory](https://directory.ob.forgerock.financial)
- From the Directory dashboard, create a new software statement, and download the transport certificate and private key
- Configure Postman to use this client certificate and key for the hosts `default.iplatform.example.com`, `default.bank.example.com`, `jwkms.ob.forgerock.financial` and `matls.service.directory.ob.forgerock.financial`

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

