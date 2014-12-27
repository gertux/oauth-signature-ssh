package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;

import be.hobbiton.ssh.key.Asn1Stream.ASN1EncodingException;

import com.sun.jersey.core.util.Base64;

/**
 * A {@link RSAPrivateKey} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshRsaPrivateKey implements RSAPrivateKey {
	private static final long serialVersionUID = -8166432012264089085L;
	public static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
	public static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";
	private BigInteger modulus;
	private BigInteger privateExponent;
	private BigInteger publicExponent;
	private BigInteger version;
	private byte[] bytes;

	public SshRsaPrivateKey(String keyString) throws SshRsaPrivateKeyException {
		int beginIndex = keyString.indexOf(BEGIN_RSA_PRIVATE_KEY);
		if (beginIndex == -1) {
			throw new SshRsaPrivateKeyException(BEGIN_RSA_PRIVATE_KEY + " not found");
		}
		int endIndex = keyString.lastIndexOf(END_RSA_PRIVATE_KEY);
		if (endIndex == -1) {
			throw new SshRsaPrivateKeyException(END_RSA_PRIVATE_KEY + " not found");
		}
		String cleanKeyString = keyString.substring(beginIndex + BEGIN_RSA_PRIVATE_KEY.length(), endIndex).replaceAll("[\r\n]", "");
		this.bytes = Base64.decode(cleanKeyString);
		try {
			Asn1Stream stream = new Asn1Stream(this.bytes);
			stream.readSequenceLength();
			this.version = stream.readInteger();
			this.modulus = stream.readInteger();
			this.publicExponent = stream.readInteger();
			this.privateExponent = stream.readInteger();
		} catch (ASN1EncodingException e) {
			throw new SshRsaPrivateKeyException(e);
		}
	}

	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	@Override
	public String getFormat() {
		return "PKCS#8";
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
	public BigInteger getPrivateExponent() {
		return this.privateExponent;
	}

	public BigInteger getPublicExponent() {
		return this.publicExponent;
	}

	public BigInteger getVersion() {
		return this.version;
	}

	public static class SshRsaPrivateKeyException extends InvalidKeyException {
		private static final long serialVersionUID = 8188239961772450980L;

		public SshRsaPrivateKeyException(String message) {
			super(message);
		}

		public SshRsaPrivateKeyException(Throwable cause) {
			super(cause);
		}
	}
}
