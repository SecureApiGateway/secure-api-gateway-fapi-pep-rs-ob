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
package com.forgerock.sapi.gateway.util;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Collection of {@link Handler} implementations which are useful for testing purposes
 */
public class TestHandlers {

    /**
     * Handler which captures the Request objects that it has processed. This is useful for testing to be able to
     * verify that the handler got called and that the Request looks as expected (especially if the filter under test
     * is making modifications).
     *
     * This handler delegates to another handler for the actual impl.
     */
    public static class TestHandler implements Handler {
        private final Handler delegateHandler;
        private final List<Request> processedRequests = new CopyOnWriteArrayList<>();

        public TestHandler(Handler delegateHandler) {
            this.delegateHandler = delegateHandler;
        }

        @Override
        public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
            processedRequests.add(request);
            return delegateHandler.handle(context, request);
        }

        public int getNumInteractions() {
            return processedRequests.size();
        }

        public boolean hasBeenInteractedWith() {
            return getNumInteractions() > 0;
        }

        public List<Request> getProcessedRequests() {
            return new ArrayList<>(processedRequests);
        }
    }

    /**
     * Handler which always returns the same response object as supplied via the constructor
     */
    public static class FixedResponseHandler extends TestHandler {
        public FixedResponseHandler(Response response) {
            super((ctxt, req) -> Promises.newResultPromise(response));
        }
    }

    /**
     * Handler which always returns a 200 response.
     */
    public static class TestSuccessResponseHandler extends FixedResponseHandler {
        public TestSuccessResponseHandler() {
            super(new Response(Status.OK));
        }
    }
}
