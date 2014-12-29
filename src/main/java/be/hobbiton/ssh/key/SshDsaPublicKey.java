package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import com.sun.jersey.core.util.Base64;

public class SshDsaPublicKey implements DSAPublicKey {
	private static final long serialVersionUID = -6879294591125282668L;
	private static final String KEY_FORMAT = "ssh-dss";
	private DSAParams dsaParams;
	private BigInteger y;
	private byte[] bytes;

	public SshDsaPublicKey(String keyString) throws SshDsaPublicKeyException {
		if (keyString == null) {
			throw new SshDsaPublicKeyException("Empty public key");
		}
		String[] contents = keyString.split(" ");
		if (contents.length != 3) {
			throw new SshDsaPublicKeyException("Invalid public key");
		}
		this.bytes = Base64.decode(contents[1]);
		SshBufferStream stream = new SshBufferStream(this.bytes);
		String keyFormat = stream.readString();
		if (!KEY_FORMAT.equals(keyFormat)) {
			throw new SshDsaPublicKeyException("Invalid public key format");
		}
		BigInteger modulus = stream.readInteger();
		BigInteger divisor = stream.readInteger();
		BigInteger generator = stream.readInteger();
		this.y = stream.readInteger();
		this.dsaParams = new SshDsaParams(modulus, divisor, generator);
	}

	@Override
	public DSAParams getParams() {
		return this.dsaParams;
	}

	@Override
	public String getAlgorithm() {
		return "DSA";
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
	public BigInteger getY() {
		return this.y;
	}

	public static class SshDsaPublicKeyException extends InvalidKeyException {
		private static final long serialVersionUID = -3908384691027431643L;

		public SshDsaPublicKeyException(String message) {
			super(message);
		}
	}
}
