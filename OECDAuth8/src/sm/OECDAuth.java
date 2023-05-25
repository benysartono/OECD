package sm;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
//import com.nimbusds.jose.util.Base64;




public class OECDAuth {
	public static void main(String[] args) {
		String encodedPwd = encode(args[0],args[1]);
		System.out.println("");
		System.out.println("");
		System.out.println("Hasil Encryptionnya: \n" + encodedPwd);
	}

	public static  String readFile(File file) {
		String data = "";
		String isiFile ="";
		try {
			File myObj = file;
			Scanner myReader = new Scanner(myObj);
			while (myReader.hasNextLine()) {
				data = data.concat(myReader.nextLine());
				isiFile = data;
			}
			myReader.close();
		} catch (FileNotFoundException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	    //System.out.println("IsiFile nya: " + isiFile);
		return isiFile;
	}

	public static RSAPublicKey readPublicKey(String fileNm) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(fileNm);


	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	    X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
	    PublicKey publicKey = certificate.getPublicKey();
	    byte[] encoded = publicKey.getEncoded();
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
		
        FileOutputStream fileOutputStream=new FileOutputStream("publicKey.gen");    
        fileOutputStream.write(rsaPublicKey.getEncoded());    
        fileOutputStream.close();    
		
		
		return rsaPublicKey;
	}

	
	public static  String encode(String payload, String certificateFileNm) {
		JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
		EncryptionMethod encryptionMethod = EncryptionMethod.A256CBC_HS512;

		try {
			//byte[] decodedKey = Base64.getDecoder().decode(encodedKeypair);

			//File publicKeyFile = new File("ppr.cts-eoi.org.cer");
			
			RSAPublicKey rsaPublicKey = readPublicKey(certificateFileNm);

			//SecretKey key = new SecretKeySpec(publicKeyBytes, 0, publicKeyBytes.length, "AES");
			JWEObject jwe = new JWEObject(
					new JWEHeader(alg, encryptionMethod),
					new Payload(payload));
			//jwe.encrypt(new AESEncrypter(rsaPublicKey));
			RSAEncrypter rsaEncrypter = new RSAEncrypter(rsaPublicKey);
			jwe.encrypt(rsaEncrypter);
			return jwe.serialize();

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
