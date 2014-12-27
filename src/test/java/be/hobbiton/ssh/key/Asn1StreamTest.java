package be.hobbiton.ssh.key;

import static be.hobbiton.ssh.key.Asn1Stream.ASN1_INTEGER_TYPE;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.Asn1Stream.ASN1EncodingException;
import be.hobbiton.ssh.key.Asn1Stream.ASN1StreamBufferOutOfBoundsException;
import be.hobbiton.ssh.key.Asn1Stream.UnexpectedASN1TypeException;

import com.sun.jersey.core.util.Base64;

public class Asn1StreamTest {
	private static final String SHORT_INTEGER = "AgMPDw8=";
	private static final BigInteger SHORT_INT = new BigInteger("986895");
	private static final String LONG_INTEGER = "AoGBAO4FGCFNwG5BIuKGuBGKHHNjnQPqLtm2l+10ndKDuhcLBp8fll2AQtcsg+w26HsTuVXtZsqXFoAQyxy8GFlkN5+RSaL0lKCD4T2jX7VguTS6/WvDdVf1Ui1jAq3xnGcSXqjuR7J83MqXNZ24EmpZj7r/M4EClCRFlHzr4YIo2KMT";
	private static final BigInteger LONG_INT = new BigInteger(
			"167143257497922545753150984148811639463980450496381634055208636140499553653564614116919631063809875286210128283357729409788161522356714428897888849038716171947879691076810057547739373453559848728249731703180888891438159016999783364247320907713130469262164370179904098632402079919881780379096262789258043499283");
	private static final String VERY_LONG_INTEGER = "AoIBAQDcPz+thCRxpnkW/miEeIguNfmaYd264WNIhLK9piWZD9Z+07NnM/ay4Gwtgp2uD37E1Re3u3yN29y+zDcIoWBBqfxyZej2skb1nRlkC1OWIc7nZehTa8xvxEWt0AIwn7M1rbr8ylvy2nd9fR8w7HqjB8yyTy7FPGy7UMtrbcKFXSCYt2h9Kch/QkBQq+zym/3FvJkXWH7yL8dybeqercqIk80POK6GRCewBxjk+juMr/+MX45BWKY4mUqkK6Xyr2KNSquJmCXlsLmnDU6f+yHQhub9anhFdPh4qMB/KOwXxtOOxW5dwBKE0GfshT28CBa3BILS4Ky56IbtswePrU2X";
	public static final BigInteger VERY_LONG_INT = new BigInteger(
			"27803616209349964853978285577598796239137408500174784770765271255148053535857568685036753174818116877337227206821128479737812884240541894295862200656944586631031827587194837601045365068384175271015777044651619690778330196206941017432733102914575320088932211059667376098790664386328301913746593618978019141158839632582149028284250265104428682485073403444562561468953402679438036816569123550017414165630224838083354222464175823491278305048411669569220224924695589302305852869283414409487896405861496848559885952284367617161506225522384064125045260609313413818668646398112754843243211392132600565121677810712162377485719");
	private static final String BOOLEAN_TRUE = "AQEB";
	private static final String SEQUENCEBODY = "AgMPDw8CgYEA7gUYIU3AbkEi4oa4EYocc2OdA+ou2baX7XSd0oO6FwsGnx+WXYBC1yyD7DboexO5Ve1mypcWgBDLHLwYWWQ3n5FJovSUoIPhPaNftWC5NLr9a8N1V/VSLWMCrfGcZxJeqO5Hsnzcypc1nbgSalmPuv8zgQKUJEWUfOvhgijYoxM=";

	@Test
	public void testReadShortInteger() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(SHORT_INTEGER));
		assertEquals(SHORT_INT, asn.readInteger());
	}

	@Test
	public void testReadLongInteger() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(LONG_INTEGER));
		assertEquals(LONG_INT, asn.readInteger());
	}

	@Test
	public void testReadVeryLongInteger() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(VERY_LONG_INTEGER));
		assertEquals(VERY_LONG_INT, asn.readInteger());
	}

	@Test
	public void testReadSequenceBody() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(SEQUENCEBODY));
		assertEquals(SHORT_INT, asn.readInteger());
		assertEquals(LONG_INT, asn.readInteger());
	}

	@Test(expected = ASN1StreamBufferOutOfBoundsException.class)
	public void testShortLength() throws Exception {
		Asn1Stream asn = new Asn1Stream(new byte[] { ASN1_INTEGER_TYPE, -127 });
		asn.readInteger();
	}

	@Test(expected = ASN1StreamBufferOutOfBoundsException.class)
	public void testShortIntegerContents() throws Exception {
		Asn1Stream asn = new Asn1Stream(new byte[] { ASN1_INTEGER_TYPE, 4, 0, 0, 1 });
		asn.readInteger();
	}

	@Test(expected = ASN1EncodingException.class)
	public void testNullConstructor() throws Exception {
		new Asn1Stream(null);
	}

	@Test(expected = ASN1EncodingException.class)
	public void testEmptyConstructor() throws Exception {
		new Asn1Stream(new byte[] {});
	}

	@Test(expected = UnexpectedASN1TypeException.class)
	public void testReadIntegerWrongType() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(BOOLEAN_TRUE));
		asn.readInteger();
	}

	@Test(expected = UnexpectedASN1TypeException.class)
	public void testReadSequenceLengthWrongType() throws Exception {
		Asn1Stream asn = new Asn1Stream(Base64.decode(BOOLEAN_TRUE));
		asn.readSequenceLength();
	}
}
