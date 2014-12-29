package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

/**
 * A {@link DSAPublicKey} implementation for SSH DSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SshDsaPublicKey extends SshPublicKey implements DSAPublicKey {
	private static final long serialVersionUID = -6879294591125282668L;
	private static final String KEY_FORMAT = "ssh-dss";
	private DSAParams dsaParams;
	private BigInteger y;

	public SshDsaPublicKey(String keyString) throws SshPublicKeyException {
		super(keyString);
		SshBufferStream stream = new SshBufferStream(getEncoded());
		String keyFormat = stream.readString();
		if (!KEY_FORMAT.equals(keyFormat)) {
			throw new SshPublicKeyException("Invalid public key format");
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
	public BigInteger getY() {
		return this.y;
	}

	@Override
	protected String getKeyFormat() {
		return KEY_FORMAT;
	}
}
