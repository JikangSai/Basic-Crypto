import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

class ObjectServer implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	byte[] cipher;
	byte[] mac;	
	ObjectServer(byte[] cipher, byte[]mac){
		this.cipher = cipher;
		this.mac = mac;
	}
}

class ObjectClient implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	byte[] cipher;
	byte[] message;	
	ObjectClient(byte[] cipher, byte[] message){
		this.cipher = cipher;
		this.message = message;
	}
}

public class Server{

	public static PrivateKey getPrivateKey(String path) throws Exception {	
		File filePrivateKey = new File(path);
		FileInputStream fis = new FileInputStream(path);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		return keyFactory.generatePrivate(privateKeySpec);
	}

	public static PublicKey getPublicKey(String path) throws Exception {
		
		File filePublicKey = new File(path);
		FileInputStream inputStream = new FileInputStream(path);
		byte[] PublicKeyEncoded = new byte[(int) filePublicKey.length()];
		inputStream.read(PublicKeyEncoded);
		inputStream.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(PublicKeyEncoded);
		return keyFactory.generatePublic(publicKeySpec);
	}

	public static byte[] getMAC(byte[] keyByte, String message) throws Exception{		      
            SecretKey key = new SecretKeySpec(keyByte, 0, keyByte.length, "AES");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(key);
            byte[] messageByte = message.getBytes();            
            byte[] result = mac.doFinal(messageByte);
            return result;
	}

	public static byte[] encryptionAES(String message, byte[] key) throws Exception {
		String initial = "encrypt";
        IvParameterSpec iv = new IvParameterSpec(initial.getBytes());
        SecretKeySpec secretkeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretkeySpec, iv);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
	}

	public static void main(String argv[]) throws Exception{
		Scanner reader = new Scanner(System.in);
		System.out.println("Enter Server's port number: ");
		String portNumber = reader.nextLine();
		System.out.println("Enter Server's private key: ");
		String sPrivateKey = reader.nextLine();
		System.out.println("Enter Client's public key: ");
		String cPublicKey = reader.nextLine();
		System.out.println("Enter file: ");
		String file = reader.nextLine();
		String FilePath = file;
		
		ServerSocket serverSocket = new ServerSocket(Integer.parseInt(portNumber));
		while(true) {
			Socket connectionSocket = serverSocket.accept();
			ObjectInputStream inStream = new ObjectInputStream(connectionSocket.getInputStream());
			ObjectClient received = (ObjectClient) inStream.readObject();
			PrivateKey privateKey = getPrivateKey(sPrivateKey);
			PublicKey publicKey = getPublicKey(cPublicKey);
		    Cipher decryptCipher = Cipher.getInstance("RSA");
		    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		    byte[] plainTextDecrypt = decryptCipher.doFinal(received.cipher);        

	        Signature publicSignature = Signature.getInstance("SHA1withRSA");
	        publicSignature.initVerify(publicKey);
	        publicSignature.update(plainTextDecrypt);
	        boolean checkVerify = publicSignature.verify(received.message);			
			if(checkVerify){
				System.out.println("Received key: "+Base64.getEncoder().encodeToString(plainTextDecrypt));
			}
			else{
				System.out.println("Wrong!");
				return;
			}
			String message = new String (Files.readAllBytes(Paths.get(FilePath)));
			byte[] mac = getMAC(plainTextDecrypt, message);
			byte[] cipherText = encryptionAES(message, plainTextDecrypt);
			ObjectServer ObjectToClient = new ObjectServer(cipherText, mac);
			ObjectOutputStream outToClient = new ObjectOutputStream(connectionSocket.getOutputStream());
			outToClient.writeObject(ObjectToClient);
		}
	}
}

