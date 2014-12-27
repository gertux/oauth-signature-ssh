package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.util.Arrays;

public class Asn1Stream {
	public static final byte ASN1_INTEGER_TYPE = 0x02;
	public static final byte ASN1_SEQUENCE_TYPE = 0x30;
	private byte[] bytes;
	private int pos;

	public Asn1Stream(byte[] bytes) {
		super();
		if ((bytes == null) || (bytes.length < 1)) {
			throw new ASN1EncodingException("Content should not be empty");
		}
		this.bytes = bytes;
		this.pos = 0;
	}

	public BigInteger readInteger() {
		if (readInt() == ASN1_INTEGER_TYPE) {
			int length = readLength();
			if ((this.pos + length) > this.bytes.length) {
				throw new ASN1StreamBufferOutOfBoundsException("Unexpected end of buffer");
			}
			byte[] data = Arrays.copyOfRange(this.bytes, this.pos, this.pos + length);
			this.pos += length;
			return new BigInteger(data);
		}
		throw new UnexpectedASN1TypeException("No ASN integer");
	}

	public int readSequenceLength() {
		if (readInt() == ASN1_SEQUENCE_TYPE) {
			return readLength();
		}
		throw new UnexpectedASN1TypeException("No ASN sequence");
	}

	private int readLength() {
		int length = readInt();
		if ((length & 0x80) != 0) {
			int lengthLength = length & 0x7f;
			length = 0;
			while (lengthLength-- > 0) {
				length = (length << 8) | (readInt() & 0xff);
			}
		}
		return length;
	}

	private int readInt() {
		if (this.pos < this.bytes.length) {
			return this.bytes[this.pos++] & 0xff;
		}
		throw new ASN1StreamBufferOutOfBoundsException("Unexpected end of buffer");
	}

	public static class ASN1EncodingException extends RuntimeException {
		private static final long serialVersionUID = 3987778424770050143L;

		public ASN1EncodingException(String message) {
			super(message);
		}
	}

	public static class ASN1StreamBufferOutOfBoundsException extends ASN1EncodingException {
		private static final long serialVersionUID = -2240419807132246396L;

		public ASN1StreamBufferOutOfBoundsException(String message) {
			super(message);
		}
	}

	public static class UnexpectedASN1TypeException extends ASN1EncodingException {
		private static final long serialVersionUID = -2572653978008290090L;

		public UnexpectedASN1TypeException(String message) {
			super(message);
		}
	}
}
