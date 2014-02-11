package net.hetimatan.util.hmac;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import net.hetimatan.util.io.ByteArrayBuilder;

//rfc 2104
public class Hmac {

	public static void main(String[] args) {
		Random r  = new Random(System.currentTimeMillis());
		byte[] key = 
				ByteArrayBuilder.parseLong(r.nextLong(), ByteArrayBuilder.BYTEORDER_BIG_ENDIAN);
		byte[] timestamp = 
				ByteArrayBuilder.parseLong(System.currentTimeMillis(), ByteArrayBuilder.BYTEORDER_BIG_ENDIAN);
		
	}
	public static final int SHA1 = 0;
	private int mType = SHA1;
	public Hmac(int type) {
		mType = type;
	}

	public static int getBlockSizePerByte(int type) {
		if(type == SHA1) {
			return 20;
		}
		return 20;
	}

	//
	// Hash(password XOR opad , Hash(password XOR ipad , targetData))
	//
	// Hash method is sha1 or ..
	// opad 
	//    0x36 xor key
	// ipad
	//    0x5C xor key
	// password
	//      
	// 
	public byte[] hmac(byte[] password, byte[] targetData) throws NoSuchAlgorithmException {
		int blocksize = getBlockSizePerByte(mType);
		byte[] keyforCalc = new byte[blocksize];

		// (1) append zeros to the end of K to create a B byte string
	    //    (e.g., if K is of length 20 bytes and B=64, then K will be
	    //     appended with 44 zero bytes 0x00)
		if (password.length <= blocksize) {
			Arrays.fill(keyforCalc, (byte)0);
			System.arraycopy(password, 0, keyforCalc, 0, password.length);
		} else {
			Arrays.fill(keyforCalc, (byte)0);
			keyforCalc = hash(password);
		}

		//(2) XOR (bitwise exclusive-OR) the B byte string computed in step	
		//(1) with ipad
		//        ipad = the byte 0x36 repeated B times
		byte[] ipad = new byte[keyforCalc.length];
		for(int i=0;i<ipad.length;i++){
			ipad[i] = (byte)(0xFF&(keyforCalc[i]^0x36));}//00110110

		//  (3) append the stream of data 'text' to the B byte string resulting
		// 		from step (2)
		byte[] ipadHash = null;
		{
			byte[] tmp = new byte[ipad.length+targetData.length];
			System.arraycopy(ipad, 0, tmp, 0, ipad.length);
			System.arraycopy(targetData, 0, tmp, ipad.length, targetData.length);
			// (4) apply H to the stream generated in step (3)
			ipadHash = hash(tmp);
		}

		byte[] opadHash= null;
		{
			// (5) XOR (bitwise exclusive-OR) the B byte string computed in
			// 	   step (1) with opad
			byte[] opad = new byte[keyforCalc.length];
			for(int i=0;i<ipad.length;i++){
				opad[i] = (byte)(0xFF&(keyforCalc[i]^0x5C));}//01011100

			// (6) append the H result from step (4) to the B byte string
			//     resulting from step (5)
			byte[] tmp = new byte[opad.length+ipadHash.length];
			System.arraycopy(opad, 0, tmp, 0, opad.length);
			System.arraycopy(opadHash, 0, tmp, opad.length, opadHash.length);
			// (7) apply H to the stream generated in step (6) and output
			//     the result
			opadHash = hash(tmp);
		}

		return opadHash;
	}

	public static byte[] hash(byte[] input) throws NoSuchAlgorithmException {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA1");
		md.update(input);
		return md.digest();
	}
}
