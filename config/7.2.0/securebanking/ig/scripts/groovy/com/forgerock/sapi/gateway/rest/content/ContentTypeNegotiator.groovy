package com.forgerock.sapi.gateway.rest.content

import org.forgerock.http.util.MultiValueMap
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Class to help determine a suitable media type to return
 */
public class ContentTypeNegotiator {

    private final Logger logger = LoggerFactory.getLogger(getClass())

    private final String logPrefix

    private TreeMap<Float, List<String>> mediaTypesMap = [:]

    private List<String> supportedContentTypes;

    public ContentTypeNegotiator(String logPrefix, List<String> supportedContentTypes) {
        this.logPrefix = logPrefix
        this.supportedContentTypes = supportedContentTypes
    }

    /**
     * Process the accepte header against a list of media types supported for the response
     * returns a string representing the supported media type that best meets the media 
     * types accepted by the client
     */
    String getBestContentType(Header acceptHeader) {
        logger.debug('{}accept header contains {}', logPrefix, acceptHeader)

        buildMapOfAcceptableMediaTypes(acceptHeader)
        String bestContentType = findHighestWeightedSupportedMediaType()
        logger.debug("{}Best Content Type is {}", logPrefix, bestContentType)
        return bestContentType
    }

    private void buildMapOfAcceptableMediaTypes(Header acceptHeader) {
        MultiValueMap<Float, List<String>> sortedContentTypes = new MultiValueMap(mediaTypesMap)
        String[] acceptValues = acceptHeader.getValues()
        for (String acceptValue in acceptValues) {
            String[] contentTypes = acceptValue.split(',')
            for (String contentType in contentTypes) {
                String[] contentTypeAndQ = contentType.split(';')
                if (contentTypeAndQ.size() == 1) {
                    Float defaultWeight = 1.0f
                    sortedContentTypes.add( defaultWeight , contentTypeAndQ[0].trim().toLowerCase())
                } else if (contentTypeAndQ.size() == 2){
                    String qValueStr = contentTypeAndQ[1].replace('q=', '')
                    Float qValue = Float.valueOf(qValueStr).floatValue()
                    sortedContentTypes.add(qValue, contentTypeAndQ[0].trim().toLowerCase())
                } else {
                    logger.debug('{}Invalid content type entry found in Accept header {}', logPrefix, acceptHeader)
                }
            }
        }
    }

    private String findHighestWeightedSupportedMediaType() {
        def reverseSortedContentTypes = mediaTypesMap.descendingMap()
        for (content in reverseSortedContentTypes){
            List<String> values = content.value
            logger.debug('{}{} weighting is {}', logPrefix, values, content.key)
            List matchingContentTypes = values.intersect(supportedContentTypes)
            if (!matchingContentTypes.isEmpty()) {
                logger.debug('{}Found matching content types {}', logPrefix, matchingContentTypes)
                return matchingContentTypes[0]
            }
        }
        logger.info('{}No matching media types', logPrefix)
        return ''
    }
}