package be.hobbiton.jersey.oauth.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import be.hobbiton.ssh.key.SshRsaPrivateKey;
import be.hobbiton.ssh.key.SshRsaPublicKey;

import com.sun.jersey.core.util.Base64;
import com.sun.jersey.oauth.signature.InvalidSecretException;
import com.sun.jersey.oauth.signature.OAuthSecrets;
import com.sun.jersey.oauth.signature.OAuthSignatureMethod;

/**
 * An {@link OAuthSignatureMethod} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 */

public class SSH_RSA implements OAuthSignatureMethod {
	public static final String NAME = "SSH-RSA";
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public String sign(String elements, OAuthSecrets secrets) throws InvalidSecretException {
		Signature signature;
		try {
			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		try {
			SshRsaPrivateKey privateKey = new SshRsaPrivateKey(secrets.getConsumerSecret());
			signature.initSign(privateKey);
			signature.update(elements.getBytes());
			return new String(Base64.encode(signature.sign()));
		} catch (InvalidKeyException e) {
			throw new InvalidSshRsaSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshRsaSecretException(e);
		}
	}

	@Override
	public boolean verify(String elements, OAuthSecrets secrets, String signatureStr) throws InvalidSecretException {
		Signature signature;
		try {
			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		try {
			SshRsaPublicKey publicKey = new SshRsaPublicKey(secrets.getConsumerSecret());
			signature.initVerify(publicKey);
			signature.update(elements.getBytes());
			return signature.verify(Base64.decode(signatureStr));
		} catch (InvalidKeyException e) {
			throw new InvalidSshRsaSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshRsaSecretException(e);
		}
	}

	public static class InvalidSshRsaSecretException extends InvalidSecretException {
		private static final long serialVersionUID = -8632101090930181119L;
		public InvalidSshRsaSecretException(Throwable cause) {
			super(cause.getMessage());
			super.setStackTrace(cause.getStackTrace());
		}
	}
}
