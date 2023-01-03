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