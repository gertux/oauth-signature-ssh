package be.hobbiton.jersey.oauth.signature;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import be.hobbiton.ssh.key.SshDsaPrivateKey;
import be.hobbiton.ssh.key.SshDsaPublicKey;

import com.sun.jersey.oauth.signature.OAuthSignatureMethod;

/**
 * An {@link OAuthSignatureMethod} implementation for SSH DSA Keys
 *
 * @author <a href="mailto:gert@hobbiton.be">Gert Dewit</a>
 *
 */
public class SSH_DSA extends SshOAuthSignatureMethod implements OAuthSignatureMethod {
	public static final String NAME = "SSH-DSA";
	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";

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
		return new SshDsaPrivateKey(keyString);
	}

	@Override
	protected PublicKey getPublicKey(String keyString) throws InvalidKeyException {
		return new SshDsaPublicKey(keyString);
	}
}
