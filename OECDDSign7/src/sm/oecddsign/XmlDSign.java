package sm.oecddsign;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;


public class XmlDSign {
	
	public static void runproc(String[] args) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		SignatureUtil signatureUtil = new SignatureUtil();
		
		try {
			signatureUtil.generateXMLDigitalSignature(args[0],args[1],args[2],args[3]);
		} catch (ParserConfigurationException | SAXException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		KryptoUtil kryptoUtil = new KryptoUtil();
		KryptoUtil.zipin(args[1],args[4]);
        
		String zippedSignedXMLFile = args[4];
        String encryptedZippedSignedXMLFile = args[5];
		//SecretKey secretKey = (SecretKey) kryptoUtil.getSecureRandomKey("AES",256);
		SecretKey secretKey = (SecretKey) kryptoUtil.generateKey("AES",256);
		IvParameterSpec ivParameterSpec = KryptoUtil.generateIv();
        KryptoUtil.encryptFile("AES/CBC/PKCS5PADDING", secretKey, ivParameterSpec, zippedSignedXMLFile, encryptedZippedSignedXMLFile);
        //KryptoUtil.encryptZip("AES", zippedSignedXMLFile, encryptedZippedSignedXMLFile, secretKey, ivParameterSpec);
        
        //System.out.println("SecretKey nya: " + Base64.getDecoder().decode(secretKey.getEncoded()));
        //System.out.println("IV nya: " + Base64.getDecoder().decode(ivParameterSpec.getIV()));

		byte[] keyPlusIv = concat(secretKey.getEncoded(),ivParameterSpec.getIV());
		//byte[] keyPlusIv = concat(secretKey,ivParameterSpec);
		//SecretKey keyPlusIvasKey = new SecretKeySpec(keyPlusIv, 0, keyPlusIv.length, "AES");
	    PublicKey publicKey = null;
		try {
			publicKey = new KryptoUtil().getPublicKey(args[7]);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
	    //PublicKey publicKey = new KryptoUtil().getStoredPublicKey(args[3]);  
		kryptoUtil.encryptSecretKey(publicKey, keyPlusIv, args[6]);
	}

	static byte[] concat(byte[]...arrays)
	{
	    // Determine the length of the result array
	    int totalLength = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        totalLength += arrays[i].length;
	    }

	    // create the result array
	    byte[] result = new byte[totalLength];

	    // copy the source arrays into the result array
	    int currentIndex = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
	        currentIndex += arrays[i].length;
	    }

	    return result;
	}
	

    
}
