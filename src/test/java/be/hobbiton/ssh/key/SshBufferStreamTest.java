package be.hobbiton.ssh.key;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.SshBufferStream.SshBufferException;
import be.hobbiton.ssh.key.SshBufferStream.SshBufferOutOfBoundsException;

import com.sun.jersey.core.util.Base64;

public class SshBufferStreamTest {
	private static final String STRING = "AAAAB3NzaC1yc2E=";
	private static final String STRING_VALUE = "ssh-rsa";
	private static final String SMALL_INTEGER = "AAAAAwEAAQ==";
	private static final BigInteger SHORT_INTEGER_VALUE = new BigInteger("65537");
	private static final String BIG_INTEGER = "AAABAQDcPz+thCRxpnkW/miEeIguNfmaYd264WNIhLK9piWZD9Z+07NnM/ay4Gwtgp2uD37E1Re3u3yN29y+zDcIoWBBqfxyZej2skb1nRlkC1OWIc7nZehTa8xvxEWt0AIwn7M1rbr8ylvy2nd9fR8w7HqjB8yyTy7FPGy7UMtrbcKFXSCYt2h9Kch/QkBQq+zym/3FvJkXWH7yL8dybeqercqIk80POK6GRCewBxjk+juMr/+MX45BWKY4mUqkK6Xyr2KNSquJmCXlsLmnDU6f+yHQhub9anhFdPh4qMB/KOwXxtOOxW5dwBKE0GfshT28CBa3BILS4Ky56IbtswePrU2X";
	private static final BigInteger BIG_INTEGER_VALUE = new BigInteger(
			"27803616209349964853978285577598796239137408500174784770765271255148053535857568685036753174818116877337227206821128479737812884240541894295862200656944586631031827587194837601045365068384175271015777044651619690778330196206941017432733102914575320088932211059667376098790664386328301913746593618978019141158839632582149028284250265104428682485073403444562561468953402679438036816569123550017414165630224838083354222464175823491278305048411669569220224924695589302305852869283414409487896405861496848559885952284367617161506225522384064125045260609313413818668646398112754843243211392132600565121677810712162377485719");
	private static final String SEQUENCE = "AAAAB3NzaC1yc2EAAAADAQAB";

	@Test
	public void testReadString() {
		SshBufferStream stream = new SshBufferStream(Base64.decode(STRING));
		assertEquals(STRING_VALUE, stream.readString());
	}

	@Test
	public void testReadSmallInteger() {
		SshBufferStream stream = new SshBufferStream(Base64.decode(SMALL_INTEGER));
		assertEquals(SHORT_INTEGER_VALUE, stream.readInteger());
	}

	@Test
	public void testReadBigInteger() {
		SshBufferStream stream = new SshBufferStream(Base64.decode(BIG_INTEGER));
		assertEquals(BIG_INTEGER_VALUE, stream.readInteger());
	}

	@Test
	public void testReadSequence() {
		SshBufferStream stream = new SshBufferStream(Base64.decode(SEQUENCE));
		assertEquals(STRING_VALUE, stream.readString());
		assertEquals(SHORT_INTEGER_VALUE, stream.readInteger());
	}

	@Test(expected = SshBufferOutOfBoundsException.class)
	public void testShortLength() throws Exception {
		SshBufferStream stream = new SshBufferStream(new byte[] { 0, 0, 7 });
		stream.readInteger();
	}

	@Test(expected = SshBufferOutOfBoundsException.class)
	public void testShortIntegerContents() throws Exception {
		SshBufferStream stream = new SshBufferStream(new byte[] { 0, 0, 0, 4, 0, 0, 1 });
		stream.readInteger();
	}

	@Test(expected = SshBufferOutOfBoundsException.class)
	public void testShortStringContents() throws Exception {
		SshBufferStream stream = new SshBufferStream(new byte[] { 0, 0, 0, 3, 115, 115 });
		stream.readString();
	}

	@Test(expected = SshBufferException.class)
	public void testNullConstructor() throws Exception {
		new SshBufferStream(null);
	}

	@Test(expected = SshBufferException.class)
	public void testEmptyConstructor() throws Exception {
		new SshBufferStream(new byte[] {});
	}
}
