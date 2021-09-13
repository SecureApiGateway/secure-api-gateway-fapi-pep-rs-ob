import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.net.URLDecoder
import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1OctetString
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.interfaces.RSAPublicKey;


/*
 * Utility funcs for parsing certificate contents
 */

class CertificateParserHelper {
    private static final EXTENDED_KEY_USAGE_OID_STRINGS = [
            "2.5.29.37.0",
            "1.3.6.1.5.5.7.3.0",
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2",
            "1.3.6.1.5.5.7.3.3",
            "1.3.6.1.5.5.7.3.4",
            "1.3.6.1.5.5.7.3.5",
            "1.3.6.1.5.5.7.3.6",
            "1.3.6.1.5.5.7.3.7",
            "1.3.6.1.5.5.7.3.8",
            "1.3.6.1.4.1.311.20.2.2",
            "1.3.6.1.5.5.7.3.9"
    ];

    private static final EXTENDED_KEY_USAGE_TEXTS = [
            "All Usages",
            "All Usages",
            "Server Authentication",
            "Client Authentication",
            "Code Signing",
            "Email Protection",
            "IPSec end system",
            "IPSec tunnel",
            "IPSec user",
            "Timestamping",
            "Smartcard Logon",
            "OCSP signer"
    ];

    private static final OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"

    private static final OID_PSD2_QC_STATEMENT = "0.4.0.19495.2"

    private static final OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
    private static final TYPE_ORGANIZATIONAL_IDENTIFIER = "OI"


    public static List<String> getExtendedKeyUsageAsText(Certificate certificate) {
      def extendedKeyUsageOidToTextMap = [EXTENDED_KEY_USAGE_OID_STRINGS, EXTENDED_KEY_USAGE_TEXTS].transpose().collectEntries{it}
      try {
        def extendedkeyusage = certificate.getExtendedKeyUsage();
        if (extendedkeyusage == null){
          return [];
        }
        def returnval = []
        extendedkeyusage.each{it->
          returnval.push(extendedKeyUsageOidToTextMap.get(it));
        }
        return returnval;
      } catch (java.security.cert.CertificateParsingException e) {
        //log.error("certificate parsing exception" + e.getLocalizedMessage(), e);
        throw e;
      }
    }


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

    public static getSubjectAltName(Certificate certificate) {
      def result=[]
      def sans = certificate.getSubjectAlternativeNames()
      try {
        if ( sans!= null) {
          sans.each {iter->
            String name = (String)iter.get(1);
            if (name != null){
              result.push(name);
            }
          }
        }
      } catch (java.security.cert.CertificateParsingException e) {
        result = e.getMessage();
      }

      return result;
    }

    /*
     * getRoles() - pull the list of roles from the QCStatements extension
     *
     * Example extension content:

       0:d=0  hl=3 l= 203 cons: SEQUENCE
       3:d=1  hl=2 l=   8 cons:  SEQUENCE
       5:d=2  hl=2 l=   6 prim:   OBJECT            :0.4.0.1862.1.1
      13:d=1  hl=2 l=  19 cons:  SEQUENCE
      15:d=2  hl=2 l=   6 prim:   OBJECT            :0.4.0.1862.1.6
      23:d=2  hl=2 l=   9 cons:   SEQUENCE
      25:d=3  hl=2 l=   7 prim:    OBJECT            :0.4.0.1862.1.6.3
      34:d=1  hl=2 l=   9 cons:  SEQUENCE
      36:d=2  hl=2 l=   7 prim:   OBJECT            :0.4.0.194121.1.2
      45:d=1  hl=3 l= 158 cons:  SEQUENCE
      48:d=2  hl=2 l=   6 prim:   OBJECT            :0.4.0.19495.2
      56:d=2  hl=3 l= 147 cons:   SEQUENCE
      59:d=3  hl=2 l= 106 cons:    SEQUENCE
      61:d=4  hl=2 l=  41 cons:     SEQUENCE
      63:d=5  hl=2 l=   7 prim:      OBJECT            :0.4.0.19495.1.4
      72:d=5  hl=2 l=  30 prim:      UTF8STRING        :Card Based Payment Instruments
     104:d=4  hl=2 l=  30 cons:     SEQUENCE
     106:d=5  hl=2 l=   7 prim:      OBJECT            :0.4.0.19495.1.3
     115:d=5  hl=2 l=  19 prim:      UTF8STRING        :Account Information
     136:d=4  hl=2 l=  29 cons:     SEQUENCE
     138:d=5  hl=2 l=   7 prim:      OBJECT            :0.4.0.19495.1.2
     147:d=5  hl=2 l=  18 prim:      UTF8STRING        :Payment Initiation
     167:d=3  hl=2 l=  29 prim:    UTF8STRING        :ForgeRock Financial Authority
     198:d=3  hl=2 l=   6 prim:    UTF8STRING        :GB-FFA
     206:d=0  hl=2 l=  13 cons: SEQUENCE
     208:d=1  hl=2 l=   9 prim:  OBJECT            :sha256WithRSAEncryption
     219:d=1  hl=2 l=   0 prim:  NULL
     221:d=0  hl=4 l= 257 prim: BIT STRING

    */


    public static getRoles(Certificate certificate, loghandler) {
        def roles = []

        byte[] qcBytes = certificate.getExtensionValue(OID_QC_STATEMENTS)

        if (qcBytes == null) {
            loghandler.warn("No QC statement")
            return null
        }

        ASN1InputStream asn1InputStream = new ASN1InputStream(qcBytes)
        ASN1Primitive derObject = asn1InputStream.readObject();

        if (!(derObject instanceof DEROctetString) ) {
            loghandler.warn("Can't get octet string from " + derObject.toString())
            return null
        }

        asn1InputStream = new ASN1InputStream(derObject.getOctets())
        ASN1Primitive baseSequence = asn1InputStream.readObject();

        if (!(baseSequence instanceof ASN1Sequence)) {
            loghandler.warn("Can't get base asn1 sequence from " + baseSequence.toString())
            return null
        }

        loghandler.debug("Parsing roles from " + baseSequence)


        def objects = baseSequence.getObjects()

        while (objects.hasMoreElements()) {
            def seq = objects.nextElement();
            if (seq instanceof ASN1Sequence) {
                def obj = seq.getObjectAt(0)
                if (obj && obj instanceof ASN1ObjectIdentifier && obj.getId() == OID_PSD2_QC_STATEMENT) {
                    def seq1 = seq.getObjectAt(1)
                    if (seq1) {
                        def seq2 = seq1.getObjectAt(0)
                        if (seq2 instanceof ASN1Sequence) {
                            def rolesSeq = seq2.getObjects()
                            while (rolesSeq.hasMoreElements()) {
                                def role = rolesSeq.nextElement()
                                if (role instanceof ASN1Sequence) {
                                    def roleObj = role.getObjectAt(0)
                                    if (roleObj instanceof ASN1ObjectIdentifier) {
                                        roles.push(roleObj.getId())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return roles
    }
}

def certToObject(Certificate certificate) {

    def object = [
      expiryDate: certificate.getNotAfter().toString(),
      subjectDN: certificate.getSubjectDN(),
      subjectDNComponents:  CertificateParserHelper.parseDN(certificate.getSubjectDN().toString()),
      subjectAlternativeNames: CertificateParserHelper.getSubjectAltName(certificate),
      eku: CertificateParserHelper.getExtendedKeyUsageAsText(certificate),
      issuerDN: certificate.getIssuerDN(),
      issuerUniqueID: certificate.getIssuerUniqueID(),
      issuerAlternativeNames: certificate.getIssuerAlternativeNames(),
      issuerX500Principal: certificate.getIssuerX500Principal(),
      subjectUniqueID: certificate.getSubjectUniqueID(),
      subjectX500Principal: certificate.getSubjectX500Principal(),
      serialNumber: certificate.getSerialNumber(),
      sigAlgName: certificate.getSigAlgName(),
      sigAlgOID: certificate.getSigAlgOID(),
      signature: certificate.getSignature(),
      type: certificate.getType(),
      version: certificate.getVersion(),
      roles: CertificateParserHelper.getRoles(certificate,logger),
      publicKey: certificate.getPublicKey(),
      privateKey: getEmbeddedPrivateKey(certificate)

    ]

    return object
}

def getEmbeddedPrivateKey(Certificate certificate) {
    if (!binding.hasVariable('routeArgPrivateKeyOid')) {
        logger.debug("No routeArgPrivateKeyOid value - not looking for private key")
        return null
    }

    byte[] encryptedPrivateKey = certificate.getExtensionValue(routeArgPrivateKeyOid)

    if (!encryptedPrivateKey) {
        logger.debug("No encrypted key in cert")
        return null
    }

    logger.debug("Got encoded encrypted private key - {} bytes",encryptedPrivateKey.length)

    ASN1OctetString octString = ASN1OctetString.fromByteArray(encryptedPrivateKey)
    encryptedPrivateKeyBytes = octString.getOctets();

    logger.debug("Got raw encrypted private key - {} bytes",encryptedPrivateKeyBytes.length)


    String keyB64 = routeArgEncryptionKey;
    logger.debug("Using decryption key " + keyB64);
    byte[] decodedKey = Base64.getDecoder().decode(keyB64);

    SecretKey decryptionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, decryptionKey);

    byte[] encodedPrivateKey = cipher.doFinal(encryptedPrivateKeyBytes);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));

    return privateKey

}


def header = request.headers.get(routeArgCertificateHeader)

if (header == null) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "No certificate header on inbound request " + routeArgCertificateHeader
    logger.error(message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String certPem = URLDecoder.decode(header.firstValue.toString())

logger.debug("Client certificate PEM: \n" + certPem)

InputStream certStream = new ByteArrayInputStream(certPem.getBytes());

CertificateFactory cf = CertificateFactory.getInstance("X.509");
Certificate cert = cf.generateCertificate(certStream);

def certObject = certToObject(cert)

logger.debug("Parsed certificate " + certObject.toString())

// Store certificate details for other filters

attributes.clientCertificate = certObject

next.handle(context, request)










