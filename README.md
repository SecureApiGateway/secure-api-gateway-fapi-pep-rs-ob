# ForgeRock DevOps and Cloud Deployment - Secure Banking Access toolkit Demo

This repository contains a demonstration deployment of the ForgeRock platform along with the ForgeRock Secure API Gateway. These access toolkit are a set of plugins and configuration for meeting the UK Open Banking requirements, 
based on the [Secure API Gateway assets](https://github.com/SecureApiGateway/SecureApiGateway).

## Read first (Environment Setup)
- [DevOps Developer's Guide](https://backstage.forgerock.com/docs/forgeops/7.1/index.html)

## Principal Folder structure

| type                        | folder                               |
|-----------------------------|--------------------------------------|
| profile master              | `config/7.2.0/securebanking/`        |
| component                   | `${profile master}/ig`               |
| environment                 | `${component}/config/${environment}` |
| shared configuration folder | `${component}/lib`                   |
| shared configuration folder | `${component}/routes`                |
| shared configuration folder | `${component}/scripts`               |
> The `shared configuration folder` are configurations shared through all environments to avoid the duplications.
> All environments will use the same lib, routes and scripts.

| type         | folder               |
|--------------|----------------------|
| staging area | `docker/7.2.0/`      |
| component    | `${staging area}/ig` |

| type        | folder                                           |
|-------------|--------------------------------------------------|
| overlay     | `kustomize/overlay/7.2.0/securebanking`          |
| defaults    | `kustomize/overlay/7.2.0/securebanking/defaults` |
| environment | `${overlay}/${environment}` except `defaults`    |
> Defaults contains the map values configuration parameters shared through all environments

> Each environment on `kustomize/overlay/7.2.0/securebanking` can override the defaults map values

## Quick Start
**Steps**
- Build IG extensions
- Build IG deployment

**Build IG extensions**
```shell
mvn clean install
```
> Each module is configured using maven plugins to copy the generated library in `config/7.2.0/securebanking/ig/lib` when necessary

**IG deployment**

To make easier the deployment for developers there is a config script to initialise the IG docker with the below arguments.
- IG Environment argument: allow to deploy any IG environment created on `configuration profile master` `config/7.2.0/securebanking/ig/config/${environment}`
  - config/7.2.0/securebanking/ig/config/dev (default)
  - config/7.2.0/securebanking/ig/config/prod
- IG mode argument:
    - development (default): this mode make able the IG UI and Studio.
    - production: no IG UI and Studio.
> The initialisation default will initialise all `IG` component with defaults values `dev environment` and `development mode`.
> The `lib`, `routes`, `scripts` folders are shared between the environments.
```bash
# Initialise config with defaults
bin/config.sh init

**************************************************************************************
Initialisation of IG 'docker/7.2.0/ig-local' for [dev] environment in [development] mode
**************************************************************************************
....
....
```
```bash
# Initialise config with arguments
bin/config.sh init --env prod --igmode production

**************************************************************************************
Initialisation of IG 'docker/7.2.0/ig-local' for [prod] environment in [production] mode
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
- https://**${RS_FQDN}**/ig/openig/studio/

## Create a new environment
See [Principal Folder structure section](#principal-folder-structure)
1. Create a new folder on `profile master` `${component}/config/` with the name of your environment.
   ```bash
   mkdir config/7.2.0/securebanking/ig/config/my-environment
   ```
1. Create the config folder on your `new-enviroment`
   ```bash
   mkdir config/7.2.0/securebanking/ig/config/my-environment/config
   ```
1. Add the configuration descriptor files for the `IG` component (you can copy them from other env):
    - admin.json
    - config.json
    - logback.xml
1. Add the environment to kustomization
   1. `mkdir kustomize/overlay/7.2.0/securebanking/my-environment`
   1. Copy the kustomization from another environment to `my-environment`
      1. Configmap.yaml
      2. kustomization.yaml
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
          path: ./kustomize/overlay/7.2.0/securebanking/my-environment
   ```
1. Prepare stage area
    ```bash
    bin/config.sh --env my-environment --igmode development
    ****************************************************************************************
    Initialisation of 'docker/7.2.0/ig' for [my-environment] environment in [development] mode
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
    - New environment `dev`
    - New environment `prod`
- There is a kustomize overlay for each environment at `kustomize/overlay/7.2.0/securebanking/${environment}` with the except of `defautls` folder that contains the defaults map values shared through `{environment}`. The default `skaffold.yaml` file uses this overlay by default
- The IG deployment (`docker/7.2.0/ig`) has been modified to include a jar file with custom filters.
- The IG configuration has been updated to increase the vertx max client header size to 16k.

## Postman Collection

This repository includes a [Postman Collection](postman) for configuring the FIDC tenant and testing the deployment. 
> Follow the instructions on [postman section](postman/readme.md) to prepare the postman client environment.

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

### Extras
#### Config map properties
- ConfigMap name: `securebanking-platform-config`
> We use this kubernetes ConfigMap to allow us to declaratively manage a group of apps that will be deployed and configured in concert for each namespace (developer environment)

| data key                | value description                |
|-------------------------|----------------------------------|
| IG_FQDN                 | Ig host name                     |
| IDENTITY_PLATFORM_FQDN  | Identity platform host name      |
| ENVIRONMENT_TYPE        | CDK / CDM / FIDC *(1)            |
| RS_FQDN                 | RS host name                     |                 
| RCS_FQDN                | RCS host name                    |               
| RCS_UI_FQDN             | RCS UI host name                 |             
| AM_REALM                | users realm                      |                     
| USER_OBJECT             | idm user object                  |                     
| IG_CLIENT_ID            | IG client id                     |                     
| IG_CLIENT_SECRET        | IG client secret                 |                        
| IG_IDM_USER             | Ig service account user          |                 
| IG_IDM_PASSWORD         | Ig service account user password |                    
| IG_AGENT_ID             | IG agent id                      |          
| IG_AGENT_PASSWORD       | IG agent password                |
| IG_RCS_SECRET           | IG RCS secret passphrase         |
| IG_SSA_SECRET           | IG SSA secret passphrase         |               
| CERT_ISSUER             | cert issuer                      |                 
| ASPSP_KEYSTORE_PATH     | ASPSP key store path for         |                        
| ASPSP_KEYSTORE_PASSWORD | ASPSP key store password         |  
| ASPSP_JWTSIGNER_ALIAS   | ASPSP jwt signer alias           |                           
| ASPSP_JWTSIGNER_KID     | ASPSP jwt signer KID             |                         
| CA_KEYSTORE_PATH        | CA key store path                |
| CA_KEYSTORE_TYPE        | CA key store type                |              
| CA_KEYSTORE_STOREPASS   | CA key store password            |                 
| CA_KEYSTORE_KEYPASS     | CA key store key password        |

**References**
- *(1) `ENVIRONMENT_TYPE`:
  - CDK value: (Cloud Developer's Kit) development identity platform
  - CDM value: CDM (Cloud Deployment Model) identity cloud platform
  - FIDC value: FIDC (Forgerock Identity Cloud) identity cloud platform
