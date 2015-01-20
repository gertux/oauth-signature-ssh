package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import java.security.interfaces.DSAParams;

import org.junit.Test;

import be.hobbiton.ssh.key.SshPublicKey.SshPublicKeyException;

public class SshDsaPublicKeyTest {
	private static final String[] KEY_PARTS = SSH_DSA_PUBLIC_KEY.split(" ");

	@Test
	public void testReadDsaPublicKey() throws SshPublicKeyException {
		SshDsaPublicKey dsaPublicKey = new SshDsaPublicKey(SSH_DSA_PUBLIC_KEY);
		DSAParams dsaParams = dsaPublicKey.getParams();
		assertNotNull(dsaParams);
		assertEquals(SSH_DSA_MODULUS, dsaParams.getP());
		assertEquals(SSH_DSA_DIVISOR, dsaParams.getQ());
		assertEquals(SSH_DSA_GENERATOR, dsaParams.getG());
		assertEquals(SSH_DSA_PUBLIC_EXPONENT, dsaPublicKey.getY());
		byte[] encoded = dsaPublicKey.getEncoded();
		assertEquals(434, encoded.length);
		byte[] encodedAgain = dsaPublicKey.getEncoded();
		assertArrayEquals(encoded, encodedAgain);
		assertNotEquals(encoded, encodedAgain);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructWrongKeyFormat() throws Exception {
		new SshDsaPublicKey(SSH_RSA_2048_PUBLIC_KEY);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructBadContents() throws Exception {
		new SshDsaPublicKey(KEY_PARTS[0] + " " + KEY_PARTS[1]);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructEmpty() throws Exception {
		new SshDsaPublicKey("");
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructNull() throws Exception {
		new SshDsaPublicKey(null);
	}
}
