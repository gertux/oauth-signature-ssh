package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import com.sun.jersey.core.util.Base64;

/**
 * A {@link RSAPublicKey} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshRsaPublicKey implements RSAPublicKey {
	private static final long serialVersionUID = 2573878825772029598L;
	private static final String KEY_FORMAT = "ssh-rsa";
	private BigInteger modulus;
	private BigInteger exponent;
	private byte[] bytes;

	public SshRsaPublicKey(String keyString) throws SshRsaPublicKeyException {
		if (keyString == null) {
			throw new SshRsaPublicKeyException("Empty public key");
		}
		String[] contents = keyString.split(" ");
		if (contents.length != 3) {
			throw new SshRsaPublicKeyException("Invalid public key");
		}
		this.bytes = Base64.decode(contents[1]);
		SshBufferStream stream = new SshBufferStream(this.bytes);
		String keyFormat = stream.readString();
		if (!KEY_FORMAT.equals(keyFormat)) {
			throw new SshRsaPublicKeyException("Invalid public key format");
		}
		this.exponent = stream.readInteger();
		this.modulus = stream.readInteger();
	}

	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	@Override
	public String getFormat() {
		return "X.509";
	}

	@Override
	public byte[] getEncoded() {
		return this.bytes;
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public BigInteger getPublicExponent() {
		return this.exponent;
	}

	public static class SshRsaPublicKeyException extends InvalidKeyException {
		private static final long serialVersionUID = 3918627693069578350L;

		public SshRsaPublicKeyException(String message) {
			super(message);
		}
	}

}
