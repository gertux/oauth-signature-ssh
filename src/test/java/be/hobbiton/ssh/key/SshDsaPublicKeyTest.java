package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import java.security.interfaces.DSAParams;

import org.junit.Test;

import be.hobbiton.ssh.key.SshDsaPublicKey.SshDsaPublicKeyException;

public class SshDsaPublicKeyTest {
	private static final String[] KEY_PARTS = SSH_DSA_PUBLIC_KEY.split(" ");

	@Test
	public void testReadDsaPublicKey() throws SshDsaPublicKeyException {
		SshDsaPublicKey dsaPublicKey = new SshDsaPublicKey(SSH_DSA_PUBLIC_KEY);
		DSAParams dsaParams = dsaPublicKey.getParams();
		assertNotNull(dsaParams);
		assertEquals(SSH_DSA_MODULUS, dsaParams.getP());
		assertEquals(SSH_DSA_DIVISOR, dsaParams.getQ());
		assertEquals(SSH_DSA_GENERATOR, dsaParams.getG());
		assertEquals(SSH_DSA_PUBLIC_EXPONENT, dsaPublicKey.getY());
	}

	@Test(expected = SshDsaPublicKeyException.class)
	public void testConstructWrongKeyFormat() throws SshDsaPublicKeyException {
		new SshDsaPublicKey(SSH_RSA_2048_PUBLIC_KEY);
	}

	@Test(expected = SshDsaPublicKeyException.class)
	public void testConstructBadContents() throws SshDsaPublicKeyException {
		new SshDsaPublicKey(KEY_PARTS[0] + " " + KEY_PARTS[1]);
	}

	@Test(expected = SshDsaPublicKeyException.class)
	public void testConstructEmpty() throws SshDsaPublicKeyException {
		new SshDsaPublicKey("");
	}

	@Test(expected = SshDsaPublicKeyException.class)
	public void testConstructNull() throws SshDsaPublicKeyException {
		new SshDsaPublicKey(null);
	}
}
