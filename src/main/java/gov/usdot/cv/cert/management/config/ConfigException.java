package gov.usdot.cv.cert.management.config;

public class ConfigException extends Exception {

	private static final long serialVersionUID = -1011704637837676718L;

	public ConfigException(String message) {
		super(message);
    }
	
	public ConfigException(Throwable cause) {
		super(cause);
    }

    public ConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
