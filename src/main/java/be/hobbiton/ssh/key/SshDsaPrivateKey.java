package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

import be.hobbiton.ssh.key.Asn1Stream.ASN1EncodingException;

/**
 * A {@link DSAPrivateKey} implementation for SSH DSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshDsaPrivateKey extends SshPrivateKey implements DSAPrivateKey {
	private static final long serialVersionUID = 5810834239555800311L;
	public static final String BEGIN_DSA_PRIVATE_KEY = "-----BEGIN DSA PRIVATE KEY-----";
	public static final String END_DSA_PRIVATE_KEY = "-----END DSA PRIVATE KEY-----";
	private DSAParams dsaParams;
	private BigInteger x;
	private BigInteger y;
	private BigInteger version;

	public SshDsaPrivateKey(String keyString) throws SshPrivateKeyException {
		super(keyString);
		try {
			Asn1Stream stream = new Asn1Stream(getEncoded());
			stream.readSequenceLength();
			this.version = stream.readInteger();
			BigInteger modulus = stream.readInteger();
			BigInteger divisor = stream.readInteger();
			BigInteger generator = stream.readInteger();
			this.y = stream.readInteger();
			this.x = stream.readInteger();
			this.dsaParams = new SshDsaParams(modulus, divisor, generator);
		} catch (ASN1EncodingException e) {
			throw new SshPrivateKeyException(e);
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
	public BigInteger getX() {
		return this.x;
	}

	public BigInteger getY() {
		return this.y;
	}

	public BigInteger getVersion() {
		return this.version;
	}

	@Override
	protected String getKeyPrefix() {
		return BEGIN_DSA_PRIVATE_KEY;
	}

	@Override
	protected String getKeySuffix() {
		return END_DSA_PRIVATE_KEY;
	}
}
