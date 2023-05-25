package sm.oecddsign;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class XmlVD {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		if(args[0] == "V") {
			System.out.println("Ada dalam CmlVD main");
			XmlVSign xmlVSign = new XmlVSign();
			try {
				xmlVSign.runproc(args[1], args[2], args[3], args[4], args[5], args[6]);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		}

	}

}
