/*
 * Copyright © 2020-2026 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.jwt

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jwt.Jwt


class JwtUtils {

    static private final Logger logger = LoggerFactory.getLogger(getClass())

    static Jwt getSignedJwtFromString(String logPrefix, String jwtAsString, String jwtName){
        logger.debug(logPrefix + "Parsing jwt {}", jwtName);
        Jwt jwt
        try {
            jwt = new JwtReconstruction().reconstructJwt(jwtAsString, SignedJwt.class)
        } catch (e) {
            logger.warn(logPrefix + "failed to decode registration request JWT", e)
            return null
        }
        return jwt
    }

    static JwtClaimsSet getClaimsFromSignedJwtAsString(String logPrefix, String jwtAsString, String jwtName){
        Jwt jwt = getJwtFromString(logPrefix, jwtAsString, jwtName)
        return jwt.getClaimsSet()
    }

    static boolean hasExpired(JwtClaimsSet claimSet){
        Boolean hasExpired = false
        Date expirationTime = claimSet.getExpirationTime()
        if (expirationTime.before(new Date())) {
            hasExpired = true
        }
        return hasExpired
    }

}