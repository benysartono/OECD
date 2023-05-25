package sm.oecddsign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
//import java.lang.ref.Reference;
import java.util.Collections;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.crypto.dsig.Reference;

public class XmlDSign {
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		
		try {
			generateXMLDigitalSignature(args[0],args[1],args[2],args[3]);
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
		//byte[] ivParameterSpec = KryptoUtil.getRandomIVWithSize(16);
        KryptoUtil.encryptFile("AES/CBC/PKCS5PADDING", secretKey, ivParameterSpec, zippedSignedXMLFile, encryptedZippedSignedXMLFile);
        //KryptoUtil.encryptZip("AES", zippedSignedXMLFile, encryptedZippedSignedXMLFile, secretKey, ivParameterSpec);
        
        //System.out.println("SecretKey nya: " + Base64.getDecoder().decode(secretKey.getEncoded()));
        //System.out.println("IV nya: " + Base64.getDecoder().decode(ivParameterSpec.getIV()));

		byte[] keyPlusIv = concat(secretKey.getEncoded(),ivParameterSpec.getIV());
		System.out.println("keyPlusIv nya:" + Arrays.toString(keyPlusIv));
		//byte[] keyPlusIv = concat(secretKey,ivParameterSpec);
		SecretKey keyPlusIvasKey = new SecretKeySpec(keyPlusIv, 0, keyPlusIv.length, "AES");
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
	
	public static void generateXMLDigitalSignature(String originalXmlFilePath,  
		    String destnSignedXmlFilePath, String privateKeyFilePath, String publicKeyFilePath) throws ParserConfigurationException, SAXException, IOException {
		
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			DocumentBuilder db = dbf.newDocumentBuilder();
		    
			//Get the XML Document object  
		    Document doc = db.parse(new File(originalXmlFilePath));  
		    
		    //Create XML Signature Factory  
		    XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");  
		    PrivateKey privateKey = null;
			/*
		    try {
				privateKey = new KryptoUtil().getPrivateKey(privateKeyFilePath);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} 
			*/
		    privateKey = new KryptoUtil().getStoredPrivateKey(privateKeyFilePath);
		    DOMSignContext domSignCtx = new DOMSignContext(privateKey, doc.getDocumentElement());  
		    Reference ref = null;  
		    SignedInfo signedInfo = null;  
		    try {  
		        ref = xmlSignatureFactory.newReference("", xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null),
		         Collections.singletonList(xmlSignatureFactory.newTransform(Transform.ENVELOPED,  
		                (TransformParameterSpec) null)), null, null);  
		        signedInfo = xmlSignatureFactory.newSignedInfo(
		            xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,  
		                (C14NMethodParameterSpec) null),
		            xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),  
		            Collections.singletonList(ref));  
		    } catch (NoSuchAlgorithmException ex) {  
		        ex.printStackTrace();  
		    } catch (InvalidAlgorithmParameterException ex) {  
		        ex.printStackTrace();  
		    }  
		    
		    //Pass the Public Key File Path  
		    KeyInfo keyInfo = null;
			try {
				keyInfo = getKeyInfo(xmlSignatureFactory, publicKeyFilePath);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}  
		    //Create a new XML Signature  
		    XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);  
		    try {  
		        //Sign the document  
		        xmlSignature.sign(domSignCtx);  
		    } catch (MarshalException ex) {  
		        ex.printStackTrace();  
		    } catch (XMLSignatureException ex) {  
		        ex.printStackTrace();  
		    }  
		    //Store the digitally signed document inta a location  
		    storeSignedDoc(doc, destnSignedXmlFilePath);  
		}  

    /**
     * Method used to get the KeyInfo
     *
     * @param xmlSigFactory
     * @param publicKeyPath
     * @return KeyInfo
     */
    private static KeyInfo getKeyInfo(XMLSignatureFactory xmlSigFactory, String publicKeyPath) {
        KeyInfo keyInfo = null;
        KeyValue keyValue = null;

        
        PublicKey publicKey = null;
        try {
			publicKey = new KryptoUtil().getPublicKey(publicKeyPath);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
        //PublicKey publicKey = new KryptoUtil().getStoredPublicKey(publicKeyPath);
        KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();

        try {
            keyValue = keyInfoFact.newKeyValue(publicKey);
        } catch (KeyException ex) {
            ex.printStackTrace();
        }
        keyInfo = keyInfoFact.newKeyInfo(Collections.singletonList(keyValue));
        return keyInfo;
    }

    /*
     * Method used to store the signed XMl document
     */
    private static void storeSignedDoc(Document doc, String destnSignedXmlFilePath) {
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer trans = null;
        try {
            trans = transFactory.newTransformer();
        } catch (TransformerConfigurationException ex) {
            ex.printStackTrace();
        }
        try {
            StreamResult streamRes = new StreamResult(new File(destnSignedXmlFilePath));
            trans.transform(new DOMSource(doc), streamRes);
        } catch (TransformerException ex) {
            ex.printStackTrace();
        }
        System.out.println("XML file with attached digital signature generated successfully ...");
    }

    
}
