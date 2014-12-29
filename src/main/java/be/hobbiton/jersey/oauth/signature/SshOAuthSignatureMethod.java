package be.hobbiton.jersey.oauth.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import com.sun.jersey.core.util.Base64;
import com.sun.jersey.oauth.signature.InvalidSecretException;
import com.sun.jersey.oauth.signature.OAuthSecrets;
import com.sun.jersey.oauth.signature.OAuthSignatureMethod;

/**
 * Abstract {@link OAuthSignatureMethod} implementation that takes care of the common actions
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public abstract class SshOAuthSignatureMethod implements OAuthSignatureMethod {

	@Override
	public abstract String name();

	protected abstract String getSignatureAlgorithm();

	protected abstract PrivateKey getPrivateKey(String keyString) throws InvalidKeyException;

	protected abstract PublicKey getPublicKey(String keyString) throws InvalidKeyException;

	@Override
	public String sign(String elements, OAuthSecrets secrets) throws InvalidSecretException {
		Signature signature;
		try {
			signature = Signature.getInstance(getSignatureAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		try {
			PrivateKey privateKey = getPrivateKey(secrets.getConsumerSecret());
			signature.initSign(privateKey);
			signature.update(elements.getBytes());
			return new String(Base64.encode(signature.sign()));
		} catch (InvalidKeyException e) {
			throw new InvalidSshSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshSecretException(e);
		}
	}

	@Override
	public boolean verify(String elements, OAuthSecrets secrets, String signatureStr) throws InvalidSecretException {
		Signature signature;
		try {
			signature = Signature.getInstance(getSignatureAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		try {
			PublicKey publicKey = getPublicKey(secrets.getConsumerSecret());
			signature.initVerify(publicKey);
			signature.update(elements.getBytes());
			return signature.verify(Base64.decode(signatureStr));
		} catch (InvalidKeyException e) {
			throw new InvalidSshSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshSecretException(e);
		}
	}

	public static class InvalidSshSecretException extends InvalidSecretException {
		private static final long serialVersionUID = -8632101090930181119L;

		public InvalidSshSecretException(Throwable cause) {
			super(cause.getMessage());
			super.setStackTrace(cause.getStackTrace());
		}
	}
}
