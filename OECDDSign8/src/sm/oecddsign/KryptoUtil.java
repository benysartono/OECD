package sm.oecddsign;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is used as a cryptographic utility.
 *
 * @author <a href="mailto:debadatta.mishra@gmail.com">Debadatta Mishra</a>
 * @since 2013
 */
public class KryptoUtil {

	public SecretKey generateKey(String algorythm, int n) throws NoSuchAlgorithmException {
	    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorythm);
	    keyGenerator.init(n);
	    SecretKey key = keyGenerator.generateKey();
	    return key;
	}
	
	public Key getSecureRandomKey(String cipher, int keySize) {
	    byte[] secureRandomKeyBytes = new byte[keySize / 8];
	    SecureRandom secureRandom = new SecureRandom();
	    secureRandom.nextBytes(secureRandomKeyBytes);
	    return new SecretKeySpec(secureRandomKeyBytes, cipher);
	    //System.out.println("Key nya dalam string: " + new SecretKeySpec(secureRandomKeyBytes, cipher).toString());
	}

	public static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
	
	public static byte[] getRandomIVWithSize(int size) {
	    byte[] nonce = new byte[size];
	    new SecureRandom().nextBytes(nonce);
	    return nonce;
	}
	
	
	public static void zipin(String signedXMLFile, String zippedSignedXMLFile) throws IOException {
	        FileOutputStream fos = new FileOutputStream(zippedSignedXMLFile);
	        ZipOutputStream zipOut = new ZipOutputStream(fos);
	        File fileToZip = new File(signedXMLFile);
	        FileInputStream fis = new FileInputStream(fileToZip);
	        ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
	        zipOut.putNextEntry(zipEntry);
	        byte[] bytes = new byte[1024];
	        int length;
	        while((length = fis.read(bytes)) >= 0) {
	            zipOut.write(bytes, 0, length);
	        }
	        zipOut.close();
	        fis.close();
	        fos.close();
	    }
	
	public static void encryptZip(String algorithm, FileInputStream zippedSignedXMLFile, FileOutputStream encryptedZippedSignedXMLFile, SecretKey key,
		    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException, IOException {
		    
		    //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		    Cipher cipher = Cipher.getInstance(algorithm);
		    cipher.init(Cipher.ENCRYPT_MODE, key, iv);

		    // Wrap the output stream for encoding
		    CipherOutputStream cos = new CipherOutputStream(encryptedZippedSignedXMLFile, cipher);       

		    //wrap output with buffer stream
		    BufferedOutputStream bos = new BufferedOutputStream(cos);     

		    //wrap input with buffer stream
		    BufferedInputStream bis = new BufferedInputStream(zippedSignedXMLFile); 

		    // Write bytes
		    int b;
		    byte[] d = new byte[8];
		    while((b = bis.read(d)) != -1) {
		        bos.write(d, 0, b);
		    }
		    // Flush and close streams.
		    bos.flush();
		    bos.close();
		    bis.close();	
	}
	
	
	
	public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
		    String inputFile, String outputFile) throws IOException, NoSuchPaddingException,
		    NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException {
		    
		    Cipher cipher = Cipher.getInstance(algorithm);
		    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		    FileInputStream inputStream = new FileInputStream(inputFile);
		    FileOutputStream outputStream = new FileOutputStream(outputFile);
		    byte[] buffer = new byte[64];
		    int bytesRead;
		    while ((bytesRead = inputStream.read(buffer)) != -1) {
		        byte[] output = cipher.update(buffer, 0, bytesRead);
		        if (output != null) {
		            outputStream.write(output);
		        }
		    }
		    byte[] outputBytes = cipher.doFinal();
		    if (outputBytes != null) {
		        outputStream.write(outputBytes);
		    }
		    inputStream.close();
		    outputStream.close();
		}
	
	
	public void encryptSecretKey(PublicKey publicKey, byte[] secretKey, String fileNm) throws FileNotFoundException, IOException
	{
	    Cipher cipher = null;
	    byte[] key = null;

	    try
	    {
	        // initialize the cipher with the user's public key
	        cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        key = cipher.doFinal(secretKey);
	    }
	    catch(Exception e )
	    {
	        System.out.println ( "exception encoding key: " + e.getMessage() );
	        e.printStackTrace();
	    }
	    
	    File outputFile = new File(fileNm);
	    try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
	        outputStream.write(key);
	    }
	    
	    //return key;
	}
	
	
    /**
     * Name of the algorithm
     */
    private static final String ALGORITHM = "RSA";

    /**
     * This method is used to generate key pair based upon the provided
     * algorithm
     *
     * @return KeyPair
     */
    private KeyPair generateKeyPairs() {
        KeyPair keyPair = null;
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);
            keyPair = keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * Method used to store Private and Public Keys inside a directory
     *
     * @param dirPath to store the keys
     */
    public void storeKeyPairs(String dirPath) {
        KeyPair keyPair = generateKeyPairs();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        storeKeys(dirPath + File.separator + "publickey.key", publicKey);
        storeKeys(dirPath + File.separator + "privatekey.key", privateKey);
    }

    /**
     * Method used to store the key(Public/Private)
     *
     * @param filePath , name of the file
     * @param key
     */
    private void storeKeys(String filePath, Key key) {
        byte[] keyBytes = key.getEncoded();
        OutputStream outStream = null;
        try {
            outStream = new FileOutputStream(filePath);
            outStream.write(keyBytes);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Method used to retrieve the keys in the form byte array
     *
     * @param filePath of the key
     * @return byte array
     */
    private byte[] getKeyData(String filePath) {
        File file = new File(filePath);
        byte[] buffer = new byte[(int) file.length()];
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            fis.read(buffer);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return buffer;
    }

    /**
     * Method used to get the generated Private Key
     *
     * @param filePath of the PrivateKey file
     * @return PrivateKey
     */
    public PrivateKey getStoredPrivateKey(String filePath) {
        PrivateKey privateKey = null;
        byte[] keydata = getKeyData(filePath);
        PKCS8EncodedKeySpec encodedPrivateKey = new PKCS8EncodedKeySpec(keydata);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(encodedPrivateKey);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * Method used to get the generated Public Key
     *
     * @param filePath of the PublicKey file
     * @return PublicKey
     */
    public PublicKey getStoredPublicKey(String filePath) {
        PublicKey publicKey = null;
        byte[] keydata = getKeyData(filePath);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        X509EncodedKeySpec encodedPublicKey = new X509EncodedKeySpec(keydata);
        try {
            publicKey = keyFactory.generatePublic(encodedPublicKey);
        } catch (NullPointerException npe) {
            npe.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    
	public RSAPublicKey readPublicKey(String fileNm) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(fileNm);

	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	    X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
	    PublicKey publicKey = certificate.getPublicKey();
	    byte[] encoded = publicKey.getEncoded();
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
		return rsaPublicKey;
	}

	public PublicKey getPublicKey(String fileNm) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(fileNm);
	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	    X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
	    PublicKey publicKey = certificate.getPublicKey();
	    return publicKey;
	}	
	
	public PrivateKey getPrivateKey(String fileNm) throws Exception {
		byte[] key = Files.readAllBytes(Paths.get(fileNm));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		//X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
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
	    System.out.println("IsiFile nya: " + isiFile);
		return isiFile;
	}


}
