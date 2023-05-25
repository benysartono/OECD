package sm.oecddsign;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;


public class XmlVSign {
	
	public void runproc(String zipFileNm, String destFolder, String privateKeyFilePath, String secretKeyFilePath, String encryptedFilePath, String decryptedFilePath ) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {

		
		KryptoUtil kryptoUtil = new KryptoUtil();
		SignatureUtil signatureUtil = new SignatureUtil();
		//KryptoUtil.zipin(args[1],args[4]);
		
		kryptoUtil.unzipping(zipFileNm, destFolder);
	    PrivateKey privateKey = null;
	    privateKey = kryptoUtil.getStoredPrivateKey(privateKeyFilePath);
		byte[] decryptedFileBytes = kryptoUtil.decryptSecretKey(secretKeyFilePath, privateKey);

	    ByteBuffer bb = ByteBuffer.wrap(decryptedFileBytes);
		byte[] secretKey = new byte[32];
		byte[] iV = new byte[16];
		bb.get(secretKey, 0, secretKey.length);
		bb.get(iV, secretKey.length, iV.length);
		
		File fileInput = new File(encryptedFilePath);
		File fileOutput = new File(decryptedFilePath);
		String alg = "AES";
		
		kryptoUtil.decryptFile(alg,secretKey, iV, fileInput, fileOutput);
		//signatureUtil.verifyDigiSign(null, alg);
		
        
	}

	

    
}
