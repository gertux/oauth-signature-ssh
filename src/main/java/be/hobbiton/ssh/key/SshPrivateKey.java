package be.hobbiton.ssh.key;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

import com.sun.jersey.core.util.Base64;

/**
 * Abstract {@link PrivateKey} implementation for SSH Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public abstract class SshPrivateKey implements PrivateKey {
	private static final long serialVersionUID = 4323086330122037451L;
	private byte[] bytes;

	@Override
	public abstract String getAlgorithm();

	protected abstract String getKeyPrefix();

	protected abstract String getKeySuffix();

	protected SshPrivateKey(String keyString) throws SshPrivateKeyException {
		int beginIndex = keyString.indexOf(getKeyPrefix());
		if (beginIndex == -1) {
			throw new SshPrivateKeyException(getKeyPrefix() + " not found");
		}
		int endIndex = keyString.lastIndexOf(getKeySuffix());
		if (endIndex == -1) {
			throw new SshPrivateKeyException(getKeySuffix() + " not found");
		}
		String cleanKeyString = keyString.substring(beginIndex + getKeyPrefix().length(), endIndex).replaceAll(
				"[\r\n]", "");
		this.bytes = Base64.decode(cleanKeyString);
	}

	@Override
	public String getFormat() {
		return "PKCS#8";
	}

	@Override
	public byte[] getEncoded() {
		return this.bytes.clone();
	}

	public static class SshPrivateKeyException extends InvalidKeyException {
		private static final long serialVersionUID = 8188239961772450980L;

		public SshPrivateKeyException(String message) {
			super(message);
		}

		public SshPrivateKeyException(Throwable cause) {
			super(cause);
		}
	}
}
