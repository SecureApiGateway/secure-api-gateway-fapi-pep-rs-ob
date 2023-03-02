/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.trusteddirectories;

import java.net.MalformedURLException;
import java.net.URL;

public class TrustedDirectoryTest {

    private static URL jwks_uri;

    static {
        try {
            jwks_uri = new URL("https://jwks_uri.com");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static TrustedDirectory jwksUriBasedTrustedDirectory = new TrustedDirectory() {
        @Override
        public String getIssuer() {
            return "JwksBasedTrustedDirectory";
        }

        @Override
        public URL getDirectoryJwksUri() {
            return jwks_uri;
        }

        @Override
        public boolean softwareStatementHoldsJwksUri() {
            return true;
        }

        @Override
        public String getSoftwareStatementJwksUriClaimName() {
            return "jwksUri";
        }

        @Override
        public String getSoftwareStatementJwksClaimName() {
            return null;
        }

        @Override
        public String getSoftwareStatementOrgIdClaimName() {
            return "orgIdClaimName";
        }

        @Override
        public String getSoftwareStatementSoftwareIdClaimName() {
            return "softwareIdClaimName";
        }

        @Override
        public String getSoftwareStatementRedirectUrisClaimName() {
            return "software_redirect_uris";
        }
    };

    public static TrustedDirectory getJwksUriBasedTrustedDirectory(){
        return jwksUriBasedTrustedDirectory;
    }

}