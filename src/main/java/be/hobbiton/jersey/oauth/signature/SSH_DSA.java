package be.hobbiton.jersey.oauth.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import be.hobbiton.ssh.key.SshDsaPrivateKey;
import be.hobbiton.ssh.key.SshDsaPublicKey;

import com.sun.jersey.core.util.Base64;
import com.sun.jersey.oauth.signature.InvalidSecretException;
import com.sun.jersey.oauth.signature.OAuthSecrets;
import com.sun.jersey.oauth.signature.OAuthSignatureMethod;

public class SSH_DSA implements OAuthSignatureMethod {
	public static final String NAME = "SSH-DSA";
	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";

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
			SshDsaPrivateKey privateKey = new SshDsaPrivateKey(secrets.getConsumerSecret());
			signature.initSign(privateKey);
			signature.update(elements.getBytes());
			return new String(Base64.encode(signature.sign()));
		} catch (InvalidKeyException e) {
			throw new InvalidSshDsaSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshDsaSecretException(e);
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
			SshDsaPublicKey publicKey = new SshDsaPublicKey(secrets.getConsumerSecret());
			signature.initVerify(publicKey);
			signature.update(elements.getBytes());
			return signature.verify(Base64.decode(signatureStr));
		} catch (InvalidKeyException e) {
			throw new InvalidSshDsaSecretException(e);
		} catch (SignatureException e) {
			throw new InvalidSshDsaSecretException(e);
		}
	}

	public static class InvalidSshDsaSecretException extends InvalidSecretException {
		private static final long serialVersionUID = 4876763126184307628L;

		public InvalidSshDsaSecretException(Throwable cause) {
			super(cause.getMessage());
			super.setStackTrace(cause.getStackTrace());
		}
	}
}
