import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.x509.qualified.QCStatement
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;




import java.io.FileInputStream;
import java.io.InputStream
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import groovy.json.JsonOutput
import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.StringWriter;


import java.util.Base64
import java.security.KeyStore

String OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
String QC_STATEMENTS = "MIHLMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzAJBgcEAIvsSQECMIGeBgYEAIGYJwIwgZMwajApBgcEAIGYJwEEDB5DYXJkIEJhc2VkIFBheW1lbnQgSW5zdHJ1bWVudHMwHgYHBACBmCcBAwwTQWNjb3VudCBJbmZvcm1hdGlvbjAdBgcEAIGYJwECDBJQYXltZW50IEluaXRpYXRpb24MHUZvcmdlUm9jayBGaW5hbmNpYWwgQXV0aG9yaXR5DAZHQi1GRkE=";

// Issue new transport certificate for API Client testing
//
// Certificate has its own private key embedded as a custom extension for use by test JWMKMS service
//
// Not for live clients!

// Read in request details

def requestObj = request.entity.getJson();

String subjectCN = requestObj.org_name;
String subjectOI = requestObj.org_id;

logger.debug("Issuing certificate for CN {} OI {}",subjectCN,subjectOI)

if (!(subjectCN && subjectOI)) {
    logger.error("Didn't get all input data")
    return new Response(Status.BAD_REQUEST)
}

// Load up the CA keystore

String BC_PROVIDER = "BC";
String KEY_ALGORITHM = "RSA";
String SIGNATURE_ALGORITHM = routeArgSigningAlg;

Security.addProvider(new BouncyCastleProvider());


KeyStore keystore = KeyStore.getInstance(routeArgKeystoreType);

InputStream keystoreInputStream = new FileInputStream(routeArgKeystoreFile)

keystore.load(keystoreInputStream, routeArgKeystorePass.toCharArray());
X509Certificate caCertificate = (X509Certificate) keystore.getCertificate(routeArgKeyAlias);
PrivateKey caKey = (PrivateKey) keystore.getKey(routeArgKeyAlias, routeArgKeyPass.toCharArray());
PublicKey caPublicKey = caCertificate.getPublicKey();

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
keyPairGenerator.initialize(routeArgKeySize);

// Setup certificate start date to yesterday and end date from config

Calendar calendar = Calendar.getInstance();
calendar.add(Calendar.DATE, -1);
Date startDate = calendar.getTime();

calendar.add(Calendar.DATE, routeArgValidityDays);
Date endDate = calendar.getTime();

// Generate a new KeyPair and CSR

X500Name issuedCertSubject = new X500Name("CN=" + subjectCN + ",OID." + OID_ORGANIZATIONAL_IDENTIFIER + "=" + subjectOI);
BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

// Sign the CSR with the CA key

ContentSigner csrContentSigner = csrBuilder.build(caKey);
PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

X500Name certIssuer = new X500Name(caCertificate.getSubjectDN().getName())
X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(certIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

// Add Extensions

issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));


// Currently build fixed qcstatements with all roles
issuedCertBuilder.addExtension(Extension.qCStatements,false,Base64.getDecoder().decode(QC_STATEMENTS));

// Embed the encrypted private key in the certificate. ECB used for simplicity - not production grade

String keyB64 = routeArgEncryptionKey;
logger.debug("Using encryption key " + keyB64);
byte[] decodedKey = Base64.getDecoder().decode(keyB64);

SecretKey encryptionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
byte[] encryptedPrivateKey = cipher.doFinal(issuedCertKeyPair.getPrivate().getEncoded());

logger.debug("encrypted private key - {} bytes",encryptedPrivateKey.length)

ASN1ObjectIdentifier privateKeyOid = new ASN1ObjectIdentifier(routeArgPrivateKeyOid);
Extension privateKeyExtension = new Extension(privateKeyOid, false, encryptedPrivateKey);

issuedCertBuilder.addExtension(privateKeyExtension);

X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

// Verify the issued cert signature against the CA cert

issuedCert.verify(caCertificate.getPublicKey(), BC_PROVIDER);

// Build response with cert and private key

/*
def pemCert = Base64.getUrlEncoder().encodeToString(issuedCert.getEncoded())
def pemKey =  Base64.getUrlEncoder().encodeToString(issuedCertKeyPair.getPrivate().getEncoded())


def responseObj = [
        "x5c": pemCert,
        "key": pemKey
]
*/

StringWriter certWriter = new StringWriter();
JcaPEMWriter certPemWriter = new JcaPEMWriter(certWriter);

certPemWriter.writeObject(issuedCert);
certPemWriter.flush();
certPemWriter.close();

StringWriter keyWriter = new StringWriter();
JcaPEMWriter keyPemWriter = new JcaPEMWriter(keyWriter);

keyPemWriter.writeObject(issuedCertKeyPair.getPrivate());
keyPemWriter.flush();
keyPemWriter.close();


def pemCert = certWriter.toString();
def pemKey = keyWriter.toString();

Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","text/plain");
response.setEntity(pemCert + pemKey);

return response
