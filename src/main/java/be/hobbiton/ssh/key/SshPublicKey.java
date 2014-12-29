package be.hobbiton.ssh.key;

import java.security.InvalidKeyException;
import java.security.PublicKey;

import com.sun.jersey.core.util.Base64;

public abstract class SshPublicKey implements PublicKey {
	private static final long serialVersionUID = 7157529533196256497L;
	private byte[] bytes;

	public SshPublicKey(String keyString) throws SshPublicKeyException {
		if (keyString == null) {
			throw new SshPublicKeyException("Empty public key");
		}
		String[] contents = keyString.split(" ");
		if (contents.length != 3) {
			throw new SshPublicKeyException("Invalid public key");
		}
		this.bytes = Base64.decode(contents[1]);
	}

	@Override
	public abstract String getAlgorithm();

	protected abstract String getKeyFormat();

	@Override
	public String getFormat() {
		return "X.509";
	}

	@Override
	public byte[] getEncoded() {
		return this.bytes;
	}

	public static class SshPublicKeyException extends InvalidKeyException {
		private static final long serialVersionUID = 3918627693069578350L;

		public SshPublicKeyException(String message) {
			super(message);
		}
	}
}
