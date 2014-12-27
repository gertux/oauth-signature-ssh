package be.hobbiton.jersey.oauth.signature;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import be.hobbiton.jersey.oauth.signature.SSH_RSA.InvalidSshRsaSecretException;

import com.sun.jersey.oauth.signature.OAuthSecrets;

public class SSH_RSATest {
	private SSH_RSA signatureMethod;

	@Before
	public void setUp() throws Exception {
		this.signatureMethod = new SSH_RSA();
	}

	@Test
	public void testName() {
		assertEquals(SSH_RSA.NAME, this.signatureMethod.name());
	}

	@Test
	public void testSign() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_RSA_2048_PRIVATE_KEY).tokenSecret(TOKEN_SECRET);

		assertEquals(SSH_RSA_2048_SIGNATURE, this.signatureMethod.sign(SSH_RSA_PAYLOAD, secrets));
	}

	@Test(expected = InvalidSshRsaSecretException.class)
	public void testSignBadKey() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_RSA_2048_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		this.signatureMethod.sign(SSH_RSA_PAYLOAD, secrets);
	}

	@Test
	public void testVerify() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_RSA_2048_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		assertTrue(this.signatureMethod.verify(SSH_RSA_PAYLOAD, secrets, SSH_RSA_2048_SIGNATURE));
	}

	@Test
	public void testVerifyFailedSig() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_RSA_2048_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		assertFalse(this.signatureMethod.verify(SSH_RSA_PAYLOAD, secrets, SSH_RSA_INVALID_SIGNATURE));
	}

	@Test(expected = InvalidSshRsaSecretException.class)
	public void testVerifyBadKey() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_RSA_2048_PRIVATE_KEY).tokenSecret(TOKEN_SECRET);

		this.signatureMethod.verify(SSH_RSA_PAYLOAD, secrets, SSH_RSA_2048_SIGNATURE);
	}
}