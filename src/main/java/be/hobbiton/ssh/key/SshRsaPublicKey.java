package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * A {@link RSAPublicKey} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshRsaPublicKey extends SshPublicKey implements RSAPublicKey {
	private static final long serialVersionUID = 2573878825772029598L;
	private static final String KEY_FORMAT = "ssh-rsa";
	private BigInteger modulus;
	private BigInteger exponent;

	public SshRsaPublicKey(String keyString) throws SshPublicKeyException {
		super(keyString);
		SshBufferStream stream = new SshBufferStream(getEncoded());
		String keyFormat = stream.readString();
		if (!KEY_FORMAT.equals(keyFormat)) {
			throw new SshPublicKeyException("Invalid public key format");
		}
		this.exponent = stream.readInteger();
		this.modulus = stream.readInteger();
	}

	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public BigInteger getPublicExponent() {
		return this.exponent;
	}

	@Override
	protected String getKeyFormat() {
		return KEY_FORMAT;
	}

}
