package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

import be.hobbiton.ssh.key.Asn1Stream.ASN1EncodingException;

import com.sun.jersey.core.util.Base64;

public class SshDsaPrivateKey implements DSAPrivateKey {
	private static final long serialVersionUID = 5810834239555800311L;
	public static final String BEGIN_DSA_PRIVATE_KEY = "-----BEGIN DSA PRIVATE KEY-----";
	public static final String END_DSA_PRIVATE_KEY = "-----END DSA PRIVATE KEY-----";
	private DSAParams dsaParams;
	private BigInteger x;
	private BigInteger y;
	private BigInteger version;
	private byte[] bytes;

	public SshDsaPrivateKey(String keyString) throws SshDsaPrivateKeyException {
		int beginIndex = keyString.indexOf(BEGIN_DSA_PRIVATE_KEY);
		if (beginIndex == -1) {
			throw new SshDsaPrivateKeyException(BEGIN_DSA_PRIVATE_KEY + " not found");
		}
		int endIndex = keyString.lastIndexOf(END_DSA_PRIVATE_KEY);
		if (endIndex == -1) {
			throw new SshDsaPrivateKeyException(END_DSA_PRIVATE_KEY + " not found");
		}
		String cleanKeyString = keyString.substring(beginIndex + BEGIN_DSA_PRIVATE_KEY.length(), endIndex).replaceAll("[\r\n]", "");
		this.bytes = Base64.decode(cleanKeyString);
		try {
			Asn1Stream stream = new Asn1Stream(this.bytes);
			stream.readSequenceLength();
			this.version = stream.readInteger();
			BigInteger modulus = stream.readInteger();
			BigInteger divisor = stream.readInteger();
			BigInteger generator = stream.readInteger();
			this.y = stream.readInteger();
			this.x = stream.readInteger();
			this.dsaParams = new SshDsaParams(modulus, divisor, generator);
		} catch (ASN1EncodingException e) {
			throw new SshDsaPrivateKeyException(e);
		}
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
		return "PKCS#8";
	}

	@Override
	public byte[] getEncoded() {
		return this.bytes;
	}

	@Override
	public BigInteger getX() {
		return this.x;
	}

	public BigInteger getY() {
		return this.y;
	}

	public BigInteger getVersion() {
		return this.version;
	}

	public static class SshDsaPrivateKeyException extends InvalidKeyException {
		private static final long serialVersionUID = 1478961160692717826L;

		public SshDsaPrivateKeyException(String msg) {
			super(msg);
		}

		public SshDsaPrivateKeyException(Throwable cause) {
			super(cause);
		}
	}
}
