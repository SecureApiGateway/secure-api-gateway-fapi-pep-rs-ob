import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn


/*
 * Utility funcs for parsing certificate contents
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ParseCertificate] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

class CertificateParserHelper {
    private static final OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
    private static final TYPE_ORGANIZATIONAL_IDENTIFIER = "OI"

    public static parseDN(String dn) {
        def result = [:]
        LdapName ln = new LdapName(dn);

        for(Rdn rdn : ln.getRdns()) {
            def rdnType = rdn.getType();
            // LdapName doesn't know about OrganizationalIdentifier
            if (rdnType == ("OID." + OID_ORGANIZATIONAL_IDENTIFIER)) {
                rdnType = TYPE_ORGANIZATIONAL_IDENTIFIER
            }
            result.put(rdnType,rdn.getValue());
        }
        return result;
    }
}

def certToObject(String certPem) {
    InputStream certStream = new ByteArrayInputStream(certPem.getBytes());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Certificate certificate = cf.generateCertificate(certStream);
    def object = [
            subjectDNComponents:  CertificateParserHelper.parseDN(certificate.getSubjectDN().toString()),
    ]
    logger.debug(SCRIPT_NAME + "Parsed certificate " + object.toString())
    // Add the X509Certificate object after the logging of the parsed data to prevent the logs being spammed
    object.put("certificate", certificate)

    return object
}


def header = request.headers.get(routeArgCertificateHeader)

if (header == null) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "No certificate header on inbound request " + routeArgCertificateHeader
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String certPem = URLDecoder.decode(header.firstValue.toString())

logger.debug(SCRIPT_NAME + "Client certificate PEM: \n" + certPem)

def certObject = certToObject(certPem)

// Store certificate details for other filters
attributes.clientCertificate = certObject

next.handle(context, request)
