package gov.usdot.cv.cert.management.config;

public class CertificateManagerConfig {

	public String raServerUrl;
	public String requestPath = "/provision-application-certificate";
	public String downloadPath = "/download/application-certificate";
	public String downloadHeader = "Download-Req";
    	
	@Override
	public String toString() {
		return "CertificateManagerConfig [" +
						  "raServerUrl=" + raServerUrl +
						  "requestPath=" + requestPath +
						  "downloadPath=" + downloadPath +
						  "downloadHeader=" + downloadHeader +
				"]";
	}
	
}
