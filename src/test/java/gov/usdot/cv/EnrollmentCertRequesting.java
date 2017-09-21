package gov.usdot.cv;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.PsidGroupPermissions;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfCertificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SequenceOfPsidGroupPermissions;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.SignerIdentifier;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.ToBeSignedCertificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.VerificationKeyIndicator;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.BasePublicEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashAlgorithm;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicVerificationKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.SymmAlgorithm;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time32;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Uint8;
import gov.usdot.asn1.generated.scms.ieee1609dot2ecaendentityinterface.EcaEndEntityInterfacePDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2ecaendentityinterface.EeEcaCertRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.CommonProvisioningRequestFields;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.EeRaAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2endentityrainterface.EndEntityRaInterfacePDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScmsPDU;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.ScopedCertificateRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedAppCertProvisioningRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedCertificateRequest;
import gov.usdot.asn1.generated.scms.ieee1609dot2scmsprotocol.SignedEeEnrollmentCertRequest;
import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;
import gov.usdot.cv.security.util.Time32Helper;

public class EnrollmentCertRequesting {

	private static final Uint8 PROTOCOL_VERSION = new Uint8(3);
	
	private static CryptoProvider cryptoProvider = new CryptoProvider();
	private static CryptoHelper cryptoHelper = new CryptoHelper(cryptoProvider);
	
	public static void main(String[] args) {
		// https://wiki.campllc.org/pages/viewpage.action?pageId=58589462#UseCase2:OBEBootstrapping(Manual)-ProcessSteps
		
		// Generate verification key pair
		AsymmetricCipherKeyPair asymmetricKeyPair = cryptoProvider.getSigner().generateKeyPair();
		
		// Genreate enrollment certificate signing request (CSR) in the format of a SignedEeEnrollmentCertRequest
		//		Include request permissions (PSIDs, Geo Region, SSPs) in CSR
		//		Include lifetime in CSR
		//		Include the asymmetric public key in CSR
		//		Use the asymmetric private key to sign CSR
		SignedEeEnrollmentCertRequest signedEeEnrollmentCertRequest = buildSignedEeEnrollmentCertRequest(asymmetricKeyPair);
		
		// Write CSR to file named <enrollment pub hex>.oer, saves the file in a directory, & zips the directory contents
		
		// Send zip to SCMS operator to be processed by ECA?
		
		// Received zip file from SCMS operator containing directory containing:
		//		RA.oer = RA cert
		//		ECA.oer = ECA cert
		//		enrollment.oer = Enrollment cert
		//		enrollment.s = Enrollment cert private key reconstruction value
	
		// Verify cert works
	}
	
	private static SignedEeEnrollmentCertRequest buildSignedEeEnrollmentCertRequest(AsymmetricCipherKeyPair asymmetricKeyPair) {
		SignedEeEnrollmentCertRequest signedEeEnrollmentCertRequest = new SignedEeEnrollmentCertRequest();
		signedEeEnrollmentCertRequest.setProtocolVersion(PROTOCOL_VERSION);
		
		EeEcaCertRequest eeEcaCertRequest = buildEeEcaCertRequest((ECPublicKeyParameters)asymmetricKeyPair.getPublic());
		EcaEndEntityInterfacePDU eca_ee = 
									EcaEndEntityInterfacePDU
										.createEcaEndEntityInterfacePDUWithEeEcaCertRequest(eeEcaCertRequest);
		ScmsPDU.Content tbsRequestContent = ScmsPDU.Content.createContentWithEca_ee(eca_ee);
		
		SignedCertificateRequest signedCertificateRequest = 
						buildSignedCertificateRequest((ECPrivateKeyParameters)asymmetricKeyPair.getPrivate(), tbsRequestContent);
		signedEeEnrollmentCertRequest.setContent(
				SignedEeEnrollmentCertRequest.Content.createContentWithSignedCertificateRequest(
						new SignedEeEnrollmentCertRequest.Content.SignedCertificateRequest(signedCertificateRequest))
				);
		
		return signedEeEnrollmentCertRequest;
	}
	
	private static EeEcaCertRequest buildEeEcaCertRequest(ECPublicKeyParameters asymmetricPublicKey) {
		EeEcaCertRequest eeEcaCertRequest = new EeEcaCertRequest();
		eeEcaCertRequest.setVersion(version);
		eeEcaCertRequest.setCurrentTime(Time32Helper.dateToTime32(ClockHelper.nowDate()));
		
		ToBeSignedCertificate tbsData = buildToBeSignedCertificate(asymmetricPublicKey);
		eeEcaCertRequest.setTbsData(tbsData);
		
		return eeEcaCertRequest;
	}
	
	private static ToBeSignedCertificate buildToBeSignedCertificate(ECPublicKeyParameters asymmetricPublicKey) {
		ToBeSignedCertificate toBeSignedCertificate = new ToBeSignedCertificate();
		
		toBeSignedCertificate.setId(id);
		
		toBeSignedCertificate.setRegion(region);
		
		SequenceOfPsidGroupPermissions certRequestPermissions = new SequenceOfPsidGroupPermissions();
		PsidGroupPermissions psidGroupPermission = new 
		certRequestPermissions.add(arg0);
		toBeSignedCertificate.setCertRequestPermissions(certRequestPermissions);
		
		EccP256CurvePoint verificationKeyCurvePoint = cryptoProvider.getSigner().encodePublicKey(asymmetricPublicKey);
		toBeSignedCertificate.setVerifyKeyIndicator(
				VerificationKeyIndicator
					.createVerificationKeyIndicatorWithVerificationKey(
							PublicVerificationKey
								.createPublicVerificationKeyWithEcdsaNistP256(verificationKeyCurvePoint)));
		
		return toBeSignedCertificate;
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

	private static SignedCertificateRequest buildSignedCertificateRequest(ECPrivateKeyParameters asymmetricPrivateKey,
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
}
