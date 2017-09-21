package gov.usdot.cv.cert.management.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.apache.log4j.Logger;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.InitializationException;

import gov.usdot.asn1.generated.scms.Scms;

public class ScmsHelper {

	private static final Logger logger = Logger.getLogger(ScmsHelper.class);
	
	private static final Coder COERCoder = Scms.getCOERCoder();
	
	static {
		try {
			Scms.initialize();
		} catch (ControlTableNotFoundException e) {
			logger.error("Failed to initiliaze Scms environment ", e);
		} catch (InitializationException e) {
			logger.error("Failed to initiliaze Scms environment ", e);
		}
	}
	
	/**
	 * Encode OSS ASN.1 generated class to COER bytes
	 * @param <T> AbstractData type parameter
	 * @param data OSS ASN.1 generated class to encode
	 * @return COER encoded byte array
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	public static <T extends AbstractData> byte[] encodeCOER(T data) throws EncodeFailedException, EncodeNotSupportedException {
		ByteArrayOutputStream sink = new ByteArrayOutputStream();
		COERCoder.encode(data, sink);
		
		return sink.toByteArray();
	}

	/**
	 * Decode COER bytes to OSS ASN.1 generated class
	 * @param bytes  COER encoded bytes
	 * @param <T> AbstractData type parameter
	 * @param dataType The OSS ASN.1 generate class the bytes should decode to
	 * @return instantiation of the OSS ASN.1 generated class
	 * @throws DecodeFailedException if decoding failed
	 * @throws DecodeNotSupportedException if decoding is not supported
	 */
	public static <T extends AbstractData> T decodeCOER(byte[] bytes, T dataType) 
												throws DecodeFailedException, DecodeNotSupportedException {
		ByteArrayInputStream bytesStream = new ByteArrayInputStream(bytes);
		T data = (T)COERCoder.decode(bytesStream, dataType);
		
		return data;
	}
}
