package gov.usdot.cv.cert.management;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

import javax.net.ssl.SSLContext;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.lf5.viewer.configure.ConfigurationManager;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.OctetString;
import com.oss.asn1.UTF8String16;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.AesCcmCiphertext;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Certificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.EncryptedData;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.EncryptedDataEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.HeaderInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Ieee1609Dot2Content;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.PKRecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.RecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfCertificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfRecipientInfo;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignedDataPayload;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignerIdentifier;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SymmetricCiphertext;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.ToBeSignedData;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.BasePublicEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashAlgorithm;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Opaque;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicVerificationKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.SymmAlgorithm;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time32;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time64;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Uint8;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.AuthenticatedDownloadRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.CommonProvisioningRequestFields;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.EeRaAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.EndEntityRaInterfacePDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.RaEeAppCertProvisioningAck;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScmsPDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScopedAppCertProvisioningAck;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScopedAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScopedAuthenticatedDownloadRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScopedCertificateRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SecuredAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SecuredAuthenticatedDownloadRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SecuredScmsPDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedAppCertProvisioningAck;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedAuthenticatedDownloadRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedCertificateRequest;
import gov.usdot.cv.cert.management.config.CertificateManagerConfig;
import gov.usdot.cv.cert.management.ssl.SSLBuilder;
import gov.usdot.cv.cert.management.util.ScmsHelper;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.msg.IEEE1609p2Message;
import gov.usdot.cv.security.msg.MessageException;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;
import gov.usdot.cv.security.util.Time32Helper;
import gov.usdot.cv.security.util.Time64Helper;

public class CertificateManager {

	private static final Logger logger = Logger.getLogger(CertificateManager.class);

	private static final Uint8 PROTOCOL_VERSION = new Uint8(3);
	
	private static final String ZIP_FILE_EXTENSION = ".zip";
	
	private CertificateManagerConfig cmConfig;
	private SSLConnectionSocketFactory sslSocketFactory;
	
	private CryptoProvider cryptoProvider = null;
	private CryptoHelper cryptoHelper = null;
	
	
	
	public static CertificateManager configure(CertificateManagerConfig cmConfig) {
		CertificateManager certManager = new CertificateManager();
		certManager.cmConfig = cmConfig;
		
		SSLContext sslContext;
		if(cmConfig.keystoreFile != null && cmConfig.keystorePassword != null) {
			sslContext = SSLBuilder.buildSSLContext(cmConfig.keystoreFile, cmConfig.keystorePassword);
		}
		else {
			sslContext = SSLBuilder.buildSSLContext();
		}
		
		certManager.sslSocketFactory = SSLBuilder.buildSSLConnectionSocketFactory(sslContext);

		certManager.cryptoProvider = new CryptoProvider();
		certManager.cryptoHelper = new CryptoHelper(certManager.cryptoProvider);
		
		return certManager;
	}
	
	public void getCertificate(Certificate enrollmentCert) throws RequestException {
		// Wrap the enrollment cert as this will decode or reconstruct all the public/private keys
		CertificateWrapper enrollmentCertWrapper;
		try {
			enrollmentCertWrapper = CertificateWrapper.fromCertificate(cryptoProvider, enrollmentCert);
		} catch (EncodeFailedException | CertificateException | EncodeNotSupportedException e) {
			logger.error("Failed to wrap the enrollment certificate.", e);
			throw new RequestException("Failed to wrap the enrollment certificate.", e);
		}
		
		// Create and sign the provisioning request with the enrollment cert
		SignedAppCertProvisioningRequest signedAppCertProvisioningRequest;
		try {
			signedAppCertProvisioningRequest = buildSignedAppCertProvisioningRequest(enrollmentCertWrapper);
		} catch (EncodeFailedException | EncodeNotSupportedException e) {
			logger.error("Failed to build Signed App Cert Provisioning Request.", e);
			throw new RequestException("Failed to build Signed App Cert Provisioning Request.", e);
		}
		
		// Encrypt the provisioning request
		SecuredAppCertProvisioningRequest securedAppCertProvisioningRequest;
		try {
			securedAppCertProvisioningRequest = encryptSignedAppCertProvisioningRequest(
														enrollmentCertWrapper, signedAppCertProvisioningRequest);
		} catch (EncodeFailedException | InvalidCipherTextException | 
				 EncodeNotSupportedException | CryptoException e) {
			logger.error("Failed to encrypt the Signed App Cert Provisioning Request.", e);
			throw new RequestException("Failed to encrypt the Signed App Cert Provisioning Request.", e);
		}
		
		// Send the request to RA Server
		SignedAppCertProvisioningAck signedAppCertProvisioningAck;
		try {
			signedAppCertProvisioningAck = request(securedAppCertProvisioningRequest);
		} catch (EncodeFailedException | DecodeFailedException |
				 EncodeNotSupportedException | DecodeNotSupportedException |
				 IOException e) {
			logger.error("Failed to complete Application Certificate Provisioning request.", e);
			throw new RequestException("Failed to complete Application Certificate Provisioning request.", e);
		}
		
		// Extract the ack
		RaEeAppCertProvisioningAck raEeAck;
		try {
			raEeAck = extractRaEeAppCertProvisioningAck(signedAppCertProvisioningAck);
		} catch (EncodeFailedException | DecodeFailedException | EncodeNotSupportedException | MessageException
				| CertificateException | CryptoException | DecodeNotSupportedException e) {
			logger.error("Failed to extract RA EE Application Certificate Provisioning Ack.", e);
			throw new RequestException("Failed to extract RA EE Application Certificate Provisioning Ack.", e);
		}

		// The filename to be used is the requestHash value of the ack
		String requestHashString = Hex.encodeHexString(raEeAck.getRequestHash().byteArrayValue());
				
		// Create and sign the download request with the enrollment cert
		SignedAuthenticatedDownloadRequest signedAuthenticatedDownloadRequest = 
									buildSignedAuthenticatedDownloadRequest(raEeAck, requestHashString, enrollmentCertWrapper);
		
		// Encrypt the download request
		SecuredAuthenticatedDownloadRequest securedAuthenticatedDownloadRequest;
		try {
			securedAuthenticatedDownloadRequest = 
								encryptSignedAuthenticatedDownloadRequest(enrollmentCertWrapper, signedAuthenticatedDownloadRequest);
		} catch (EncodeFailedException | InvalidCipherTextException | EncodeNotSupportedException | CryptoException e) {
			logger.error("Failed to encrypt the Signed Authentication Download Request.", e);
			throw new RequestException("Failed to encrypt the Signed Authentication Download Request.", e);
		}
		
		// Download the cert from the RA Server
		File certZipFile;
		try {
			certZipFile = download(securedAuthenticatedDownloadRequest, requestHashString);
		} catch (EncodeFailedException | DownloadException | EncodeNotSupportedException | IOException e) {
			logger.error("Failed to download the certificate zip file.", e);
			throw new RequestException("Failed to download the certificate zip file.", e);
		}
	}
	
	private SignedAppCertProvisioningRequest buildSignedAppCertProvisioningRequest(CertificateWrapper enrollmentCertWrapper) 
																	throws EncodeFailedException, EncodeNotSupportedException {
		SignedAppCertProvisioningRequest signedAppCertProvisioningRequest = new SignedAppCertProvisioningRequest();
		signedAppCertProvisioningRequest.setProtocolVersion(PROTOCOL_VERSION);
		
		EeRaAppCertProvisioningRequest eeRaAppCertProvisioningRequest = 
				buildEeRaAppCertProvisioningRequest(enrollmentCertWrapper.getSigningPublicKey(),
													enrollmentCertWrapper.getEncryptionPublicKey());
		EndEntityRaInterfacePDU ee_ra = 
					EndEntityRaInterfacePDU
						.createEndEntityRaInterfacePDUWithEeRaAppCertProvisioningRequest(
								eeRaAppCertProvisioningRequest);
		ScmsPDU.Content tbsRequestContent = ScmsPDU.Content.createContentWithEe_ra(ee_ra);

		SignedCertificateRequest signedCertificateRequest = 
										buildSignedCertificateRequest(enrollmentCertWrapper, tbsRequestContent);
		signedAppCertProvisioningRequest.setContent(
				SignedAppCertProvisioningRequest.Content.createContentWithSignedCertificateRequest(
						new SignedAppCertProvisioningRequest.Content.SignedCertificateRequest(signedCertificateRequest)));
		
		return signedAppCertProvisioningRequest;
	}
	
	private EeRaAppCertProvisioningRequest buildEeRaAppCertProvisioningRequest(
														ECPublicKeyParameters verifyKeyParameters,
														ECPublicKeyParameters responseEncryptionKeyParameters) {
		EeRaAppCertProvisioningRequest eeRaAppCertProvisioningRequest = new EeRaAppCertProvisioningRequest();
		
		eeRaAppCertProvisioningRequest.setVersion(version);
		
		ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
		
		// Encode the verifyKey correctly
		EccP256CurvePoint verifyKeyCurvePoint = ecdsaProvider.encodePublicKey(verifyKeyParameters);
		eeRaAppCertProvisioningRequest.setVerify_key(
									PublicVerificationKey
										.createPublicVerificationKeyWithEcdsaNistP256(
												verifyKeyCurvePoint));
		
		
		//TODO: eeRaAppCertProvisioningRequest.setCert_encryption_key(cert_encryption_key);	// Optional?
		
		// Encode the responseEncryptionKey correctly
		PublicEncryptionKey responseEncryptionKey = new PublicEncryptionKey();
		EccP256CurvePoint responseEncryptionKeyCurvePoint = ecdsaProvider.encodePublicKey(responseEncryptionKeyParameters);
		responseEncryptionKey.setSupportedSymmAlg(SymmAlgorithm.aes128Ccm);
		responseEncryptionKey.setPublicKey(
									BasePublicEncryptionKey
										.createBasePublicEncryptionKeyWithEciesNistP256(
												responseEncryptionKeyCurvePoint));
		eeRaAppCertProvisioningRequest.setResponse_encryption_key(responseEncryptionKey);
		
		// Build the common
		CommonProvisioningRequestFields common = new CommonProvisioningRequestFields();
		Time32 now = Time32Helper.dateToTime32(ClockHelper.nowDate());
		common.setCurrent_time(now);
		common.setRequested_start_time(now);
		eeRaAppCertProvisioningRequest.setCommon(common);
		
		return eeRaAppCertProvisioningRequest;
	}
	
	private SecuredAppCertProvisioningRequest encryptSignedAppCertProvisioningRequest(
													CertificateWrapper enrollmentCertWrapper,
													SignedAppCertProvisioningRequest signedAppCertProvisioningRequest)
																	throws EncodeFailedException, EncodeNotSupportedException,
																			InvalidCipherTextException, CryptoException {
		SecuredAppCertProvisioningRequest securedAppCertProvisioningRequest = new SecuredAppCertProvisioningRequest();
		securedAppCertProvisioningRequest.setProtocolVersion(PROTOCOL_VERSION);
		
		byte[] clearText = Ieee1609dot2Helper.encodeCOER(signedAppCertProvisioningRequest);
		EncryptedData encryptedSignedAppCertProvisioningRequest = encrypt(enrollmentCertWrapper, clearText);
		
		securedAppCertProvisioningRequest.setContent(
				Ieee1609Dot2Content.createIeee1609Dot2ContentWithEncryptedData(encryptedSignedAppCertProvisioningRequest));
		
		return securedAppCertProvisioningRequest;
		
	}
	
	private SignedAppCertProvisioningAck request(SecuredAppCertProvisioningRequest securedAppCertProvisioningRequest)
																	throws RequestException, EncodeFailedException,
																		EncodeNotSupportedException, ClientProtocolException,
																		IOException, DecodeFailedException, DecodeNotSupportedException {
		SignedAppCertProvisioningAck signedAppCertProvisioningAck = null;
		
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();
		
		try {
			byte[] encodedProvisioningRequestBytes = ScmsHelper.encodeCOER(securedAppCertProvisioningRequest);
			
			HttpEntity requestBody = new ByteArrayEntity(encodedProvisioningRequestBytes);
			
			HttpUriRequest request = RequestBuilder.post()
														.setUri(cmConfig.raServerUrl + cmConfig.requestPath)
														.setEntity(requestBody)
														.build();
			CloseableHttpResponse response = httpclient.execute(request);
			
			int statusCode = response.getStatusLine().getStatusCode();
			byte[] responseBody = EntityUtils.toByteArray(response.getEntity());

			if (statusCode == HttpStatus.SC_OK) { //200
				// The response is a SignedAppCertProvisioningAck
				signedAppCertProvisioningAck = ScmsHelper.decodeCOER(responseBody, new SignedAppCertProvisioningAck());
				
			} else {
				throw new RequestException("Certificate Request failed. Response code: " + statusCode + " body: " + responseBody);
			}
			
		} finally {
			try { httpclient.close(); } catch (IOException ignore) {}
		}
		
		return signedAppCertProvisioningAck;
	}
	
	private RaEeAppCertProvisioningAck extractRaEeAppCertProvisioningAck(SignedAppCertProvisioningAck signedAppCertProvisioningAck)
																	throws EncodeFailedException, EncodeNotSupportedException, 
																	MessageException, CertificateException, CryptoException,
																	DecodeFailedException, DecodeNotSupportedException {
		// The SignedAppCertProvisioningAck is just an instance of Ieee1609dot2Data
		byte[] signedAckHexBytes = ScmsHelper.encodeCOER(signedAppCertProvisioningAck);
		
		IEEE1609p2Message ackAsMsg = IEEE1609p2Message.parse(signedAckHexBytes);
		SignedDataPayload ackPayload = Ieee1609dot2Helper.decodeCOER(ackAsMsg.getPayload(), new SignedDataPayload());
		
		ScopedAppCertProvisioningAck scopedAck = ScmsHelper.decodeCOER(
													ackPayload.getData().getContent().getUnsecuredData().byteArrayValue(),
													new ScopedAppCertProvisioningAck());
		
		RaEeAppCertProvisioningAck raEeAck = scopedAck.getContent().getEe_ra().getRaEeAppCertProvisioningAck();
		
		return raEeAck;
	}
	
	private SignedAuthenticatedDownloadRequest buildSignedAuthenticatedDownloadRequest(
																	RaEeAppCertProvisioningAck raEeAck,
																	String requestHashString,
																	CertificateWrapper enrollmentCertWrapper) {
		SignedAuthenticatedDownloadRequest signedAuthenticatedDownloadRequest = new SignedAuthenticatedDownloadRequest();
		signedAuthenticatedDownloadRequest.setProtocolVersion(PROTOCOL_VERSION);
		
		AuthenticatedDownloadRequest eeRaAuthenticatedDownloadRequest = new AuthenticatedDownloadRequest();
		eeRaAuthenticatedDownloadRequest.setTimestamp(Time32Helper.dateToTime32(ClockHelper.nowDate()));
		eeRaAuthenticatedDownloadRequest.setFilename(new UTF8String16(requestHashString + ZIP_FILE_EXTENSION));
		
		EndEntityRaInterfacePDU ee_ra = 
					EndEntityRaInterfacePDU
						.createEndEntityRaInterfacePDUWithEeRaAuthenticatedDownloadRequest(
								eeRaAuthenticatedDownloadRequest);
		ScmsPDU.Content tbsRequestContent = ScmsPDU.Content.createContentWithEe_ra(ee_ra);
		
		SignedCertificateRequest signedCertificateRequest =
										buildSignedCertificateRequest(enrollmentCertWrapper, tbsRequestContent);
		signedAuthenticatedDownloadRequest.setContent(
				SignedAuthenticatedDownloadRequest.Content.createContentWithSignedCertificateRequest(
						new SignedAuthenticatedDownloadRequest.Content.SignedCertificateRequest(signedCertificateRequest)));
		
		return signedAuthenticatedDownloadRequest;	
	}
	
	private SecuredAuthenticatedDownloadRequest encryptSignedAuthenticatedDownloadRequest(
												CertificateWrapper enrollmentCertWrapper,
												SignedAuthenticatedDownloadRequest signedAuthenticatedDownloadRequest)
														throws EncodeFailedException, EncodeNotSupportedException,
														InvalidCipherTextException, CryptoException {
		SecuredAuthenticatedDownloadRequest securedAuthenticatedDownloadRequest = new SecuredAuthenticatedDownloadRequest();
		securedAuthenticatedDownloadRequest.setProtocolVersion(PROTOCOL_VERSION);
		
		byte[] clearText = Ieee1609dot2Helper.encodeCOER(signedAuthenticatedDownloadRequest);
		
		EncryptedData encryptedSignedAuthenticatedDownloadRequest = encrypt(enrollmentCertWrapper, clearText);
		securedAuthenticatedDownloadRequest.setContent(
				Ieee1609Dot2Content.createIeee1609Dot2ContentWithEncryptedData(encryptedSignedAuthenticatedDownloadRequest));
		
		return securedAuthenticatedDownloadRequest;
		
	}
	
	private File download(SecuredAuthenticatedDownloadRequest securedAuthenticatedDownloadRequest, String requestHashString)
																	throws DownloadException, EncodeFailedException,
																			EncodeNotSupportedException, ClientProtocolException,
																			IOException {
		File certZipFile = null;
		
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();

		byte[] securedAuthenticatedDownloadRequestBytes = ScmsHelper.encodeCOER(securedAuthenticatedDownloadRequest);
		String base64SecuredAuthenticatedDownloadRequest = new String(Base64.encodeBase64(securedAuthenticatedDownloadRequestBytes));
		
		try {
			HttpUriRequest request = RequestBuilder.get()
														.setUri(cmConfig.raServerUrl + cmConfig.downloadPath)
														.addHeader(cmConfig.downloadHeader, base64SecuredAuthenticatedDownloadRequest)
														.build();
			CloseableHttpResponse response = httpclient.execute(request);
			
			int statusCode = response.getStatusLine().getStatusCode();
			byte[] responseBody = EntityUtils.toByteArray(response.getEntity());
			
			if (statusCode == HttpStatus.SC_OK) { //200
				certZipFile = File.createTempFile(requestHashString, ZIP_FILE_EXTENSION);
				FileUtils.writeByteArrayToFile(certZipFile, responseBody);;
			} else {
				throw new DownloadException("Certificate Download failed. Response code: " + statusCode + " body: " + responseBody);
			}
			
		} finally {
			try { httpclient.close(); } catch (IOException ignore) {}
		}
		
		return certZipFile;
	}
	
	private SignedCertificateRequest buildSignedCertificateRequest(CertificateWrapper enrollmentCertWrapper,
																	ScmsPDU.Content tbsRequestContent) {
		SignedCertificateRequest signedCertificateRequest = new SignedCertificateRequest();
		
		signedCertificateRequest.setHashId(HashAlgorithm.sha256);
		
		// Create the ScopedCertificateRequest
		ScopedCertificateRequest tbsRequest = new ScopedCertificateRequest();
		tbsRequest.setVersion(version);
		tbsRequest.setContent(tbsRequestContent);
		
		signedCertificateRequest.setTbsRequest(tbsRequest);
		
		// Create the Signer from the enrollment cert
		SignerIdentifier signer;
		if(enrollmentCertWrapper.getCertificate() != null) {
		SequenceOfCertificate seqOfCert = new SequenceOfCertificate();
		seqOfCert.add(enrollmentCertWrapper.getCertificate());
		signer = SignerIdentifier.createSignerIdentifierWithCertificate(seqOfCert);
		}
		else {
		signer = SignerIdentifier.createSignerIdentifierWithDigest(enrollmentCertWrapper.getCertID8());
		}
		signedCertificateRequest.setSigner(signer);
		
		// Create the signature
		byte[] tbsRequestBytes = Ieee1609dot2Helper.encodeCOER(tbsRequest);
		EcdsaP256SignatureWrapper ecdsaP256Signature = 
		cryptoHelper.computeSignature(tbsRequestBytes,
					enrollmentCertWrapper.getBytes(),
					enrollmentCertWrapper.getSigningPrivateKey());
		Signature signature = ecdsaP256Signature.encode();
		signedCertificateRequest.setSignature(signature);
		
		return signedCertificateRequest;
	}
	
	private EncryptedData encrypt(CertificateWrapper encryptingCert, byte[] clearText)
																	throws CryptoException, EncodeFailedException,
																	EncodeNotSupportedException, InvalidCipherTextException {
		// Generate a new symmetric key to use for encryption
		KeyParameter symmetricKey = AESProvider.generateKey();
		
		// Set up the encryption key to be the enrollment cert's public key
		ECPublicKeyParameters enrollmentCertEncryptionPublicKey = encryptingCert.getEncryptionPublicKey();
			
		EciesP256EncryptedKey eciesP256EncryptedKey = 
									cryptoProvider.getECIESProvider()
										.encodeEciesP256EncryptedKey(symmetricKey, enrollmentCertEncryptionPublicKey);
		EncryptedDataEncryptionKey encKey = 
									EncryptedDataEncryptionKey
										.createEncryptedDataEncryptionKeyWithEciesNistP256(eciesP256EncryptedKey);
		
		// Set up the recipient to be the the enrollment cert
		PKRecipientInfo certRecipInfo = new PKRecipientInfo();
		certRecipInfo.setRecipientId(encryptingCert.getCertID8());
		certRecipInfo.setEncKey(encKey);
			
		RecipientInfo recipientInfo = RecipientInfo.createRecipientInfoWithCertRecipInfo(certRecipInfo);

		SequenceOfRecipientInfo seqOfRecipients = new SequenceOfRecipientInfo();
		seqOfRecipients.add(recipientInfo);

		byte[] nonceBytes = CryptoHelper.getSecureRandomBytes(AESProvider.nonceLength);
		OctetString nonce = new OctetString(nonceBytes);
		
		byte[] ccmCipherTextBytes = cryptoHelper.encryptSymmetric(symmetricKey, nonceBytes, clearText);
		Opaque ccmCiphertext = new Opaque(ccmCipherTextBytes);
		
		AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nonce, ccmCiphertext);
		
		SymmetricCiphertext ciphertext = SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(aesCcmCiphertext);
		
		EncryptedData encryptedData = new EncryptedData(seqOfRecipients, ciphertext);
		
		return encryptedData;
	}
	
	public class RequestException extends Exception {
		
		private static final long serialVersionUID = -6524081299952445637L;

		public RequestException(String message) {
			super(message);
		}

		public RequestException(Throwable cause) {
			super(cause);
		}

		public RequestException(String message, Throwable cause) {
			super(message, cause);
		}
	}
	
	public class DownloadException extends Exception {
		
		private static final long serialVersionUID = 181710107015073592L;

		public DownloadException(String message) {
			super(message);
		}

		public DownloadException(Throwable cause) {
			super(cause);
		}

		public DownloadException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
