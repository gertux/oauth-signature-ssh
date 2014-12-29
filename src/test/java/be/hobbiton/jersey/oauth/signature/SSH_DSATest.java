package be.hobbiton.jersey.oauth.signature;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import be.hobbiton.jersey.oauth.signature.SSH_DSA.InvalidSshDsaSecretException;

import com.sun.jersey.oauth.signature.OAuthSecrets;

public class SSH_DSATest {
	private SSH_DSA signatureMethod;

	@Before
	public void setUp() throws Exception {
		this.signatureMethod = new SSH_DSA();
	}

	@Test
	public void testName() {
		assertEquals(SSH_DSA.NAME, this.signatureMethod.name());
	}

	@Test
	public void testSignAndVerify() throws Exception {
		OAuthSecrets signSecrets = new OAuthSecrets().consumerSecret(SSH_DSA_PRIVATE_KEY).tokenSecret(TOKEN_SECRET);

		String signature = this.signatureMethod.sign(SSH_DSA_PAYLOAD, signSecrets);

		OAuthSecrets verifySecrets = new OAuthSecrets().consumerSecret(SSH_DSA_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		assertTrue(this.signatureMethod.verify(SSH_DSA_PAYLOAD, verifySecrets, signature));
	}

	@Test
	public void testVerify() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_DSA_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		assertTrue(this.signatureMethod.verify(SSH_DSA_PAYLOAD, secrets, SSH_DSA_SIGNATURE));
	}

	@Test
	public void testVerifyFailedSig() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_DSA_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		assertFalse(this.signatureMethod.verify(SSH_DSA_PAYLOAD, secrets, SSH_DSA_INVALID_SIGNATURE));
	}

	@Test(expected = InvalidSshDsaSecretException.class)
	public void testVerifyBadEncodedSig() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_DSA_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		this.signatureMethod.verify(SSH_DSA_PAYLOAD, secrets, SSH_DSA_BAD_ENCODED_SIGNATURE);
	}

	@Test(expected = InvalidSshDsaSecretException.class)
	public void testSignBadKey() throws Exception {
		OAuthSecrets secrets = new OAuthSecrets().consumerSecret(SSH_DSA_PUBLIC_KEY).tokenSecret(TOKEN_SECRET);

		this.signatureMethod.sign(SSH_DSA_PAYLOAD, secrets);
	}

	@Test(expected = InvalidSshDsaSecretException.class)
	public void testVerifyBadKey() throws Exception {
		OAuthSecrets signSecrets = new OAuthSecrets().consumerSecret(SSH_DSA_PRIVATE_KEY).tokenSecret(TOKEN_SECRET);

		String signature = this.signatureMethod.sign(SSH_DSA_PAYLOAD, signSecrets);

		OAuthSecrets verifySecrets = new OAuthSecrets().consumerSecret(SSH_DSA_PRIVATE_KEY).tokenSecret(TOKEN_SECRET);

		this.signatureMethod.verify(SSH_DSA_PAYLOAD, verifySecrets, signature);
	}
}
