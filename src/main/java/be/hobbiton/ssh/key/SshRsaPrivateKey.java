package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import be.hobbiton.ssh.key.Asn1Stream.ASN1EncodingException;

/**
 * A {@link RSAPrivateKey} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshRsaPrivateKey extends SshPrivateKey implements RSAPrivateKey {
	private static final long serialVersionUID = -8166432012264089085L;
	public static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
	public static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";
	private BigInteger modulus;
	private BigInteger privateExponent;
	private BigInteger publicExponent;
	private BigInteger version;

	public SshRsaPrivateKey(String keyString) throws SshPrivateKeyException {
		super(keyString);
		try {
			Asn1Stream stream = new Asn1Stream(getEncoded());
			stream.readSequenceLength();
			this.version = stream.readInteger();
			this.modulus = stream.readInteger();
			this.publicExponent = stream.readInteger();
			this.privateExponent = stream.readInteger();
		} catch (ASN1EncodingException e) {
			throw new SshPrivateKeyException(e);
		}
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
	public BigInteger getPrivateExponent() {
		return this.privateExponent;
	}

	public BigInteger getPublicExponent() {
		return this.publicExponent;
	}

	public BigInteger getVersion() {
		return this.version;
	}

	@Override
	protected String getKeyPrefix() {
		return BEGIN_RSA_PRIVATE_KEY;
	}

	@Override
	protected String getKeySuffix() {
		return END_RSA_PRIVATE_KEY;
	}
}
