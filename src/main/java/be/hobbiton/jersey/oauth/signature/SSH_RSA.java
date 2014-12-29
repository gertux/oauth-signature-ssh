package be.hobbiton.jersey.oauth.signature;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import be.hobbiton.ssh.key.SshRsaPrivateKey;
import be.hobbiton.ssh.key.SshRsaPublicKey;

import com.sun.jersey.oauth.signature.OAuthSignatureMethod;

/**
 * An {@link OAuthSignatureMethod} implementation for SSH RSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 */

public class SSH_RSA extends SshOAuthSignatureMethod implements OAuthSignatureMethod {
	public static final String NAME = "SSH-RSA";
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

	@Override
	public String name() {
		return NAME;
	}

	@Override
	protected String getSignatureAlgorithm() {
		return SIGNATURE_ALGORITHM;
	}

	@Override
	protected PrivateKey getPrivateKey(String keyString) throws InvalidKeyException {
		return new SshRsaPrivateKey(keyString);
	}

	@Override
	protected PublicKey getPublicKey(String keyString) throws InvalidKeyException {
		return new SshRsaPublicKey(keyString);
	}
}
