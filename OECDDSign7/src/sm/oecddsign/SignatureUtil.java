package sm.oecddsign;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
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
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class SignatureUtil {


	public void generateXMLDigitalSignature(String originalXmlFilePath,  
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

	public static void verifyDigiSign(PublicKey publicKey, String originalXmlFilePath) {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true); 
		try {
			DocumentBuilder db = dbf.newDocumentBuilder();
			File initialFile = new File(originalXmlFilePath);
			Document doc = db.parse(new FileInputStream(initialFile));
			NodeList nl = doc.getElementsByTagNameNS (XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
				throw new Exception("Cannot find Signature element");
			} 
			DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0)); 
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); 
			XMLSignature signature = factory.unmarshalXMLSignature(valContext); 
			boolean coreValidity = signature.validate(valContext);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}




	/**
	 * Method used to get the KeyInfo
	 *
	 * @param xmlSigFactory
	 * @param publicKeyPath
	 * @return KeyInfo
	 */
	private KeyInfo getKeyInfo(XMLSignatureFactory xmlSigFactory, String publicKeyPath) {
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
	private void storeSignedDoc(Document doc, String destnSignedXmlFilePath) {
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
