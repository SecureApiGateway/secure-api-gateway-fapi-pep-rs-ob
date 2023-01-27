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
package com.forgerock.sapi.gateway.dcr.common;

import java.util.List;
import java.util.function.BiFunction;

import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Headers;
import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;

/**
 * Class to retrieve the media types from the accepts header for use when creating a response
 */
public class AcceptHeaderSupplier implements BiFunction<Context, Request, List<String>>  {

    @Override
    public List<String> apply(Context context, Request request) {
        Headers headers = request.getHeaders();
        Header header = headers.get("accepts");
        if(header == null){
            return List.of();
        }
        List<String> values = header.getValues();
        return values;
    }
}
