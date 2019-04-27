import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Scanner;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


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

class ObjectServer implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	byte[] cipher;
	byte[] mac;	
	ObjectServer(byte[] cipher, byte[] mac){
		this.cipher=cipher;
		this.mac=mac;
	}
}

public class Client {	
	private static byte[] encryption(String PublicKeyFile, byte[] data) 
			throws InvalidKeyException, Exception {		
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(cipher.ENCRYPT_MODE, getPublicKey(PublicKeyFile));
        byte[] cipherByte = cipher.doFinal(data);
		return cipherByte;
	}
	
	private static byte[] GetSignature(String PrivateKeyFile, byte[] data) 
			throws InvalidKeyException, Exception {		
		Signature RSA = Signature.getInstance("SHA1withRSA"); 
		RSA.initSign(getPrivateKey(PrivateKeyFile));
		RSA.update(data);
		byte[] signedMessage = RSA.sign();		
		return signedMessage;
	}
	
	public static PrivateKey getPrivateKey(String path) throws Exception {
		
		File PrivateKey = new File(path);
		FileInputStream inputStream = new FileInputStream(path);
		byte[] PrivateKeyEncoded = new byte[(int) PrivateKey.length()];
		inputStream.read(PrivateKeyEncoded);
		inputStream.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(PrivateKeyEncoded);
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
	
	public static byte[] getMAC(byte[] key, byte[] message) throws Exception{ 
		SecretKey secretkey = new SecretKeySpec(key, 0, key.length, "AES");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretkey);
        byte[] res = mac.doFinal(message);
        return res;
	}

	public static void main(String argv[]) throws Exception{
		Scanner reader = new Scanner(System.in);
		System.out.println("Enter Server's IP address: ");
		String ip = reader.nextLine();
		System.out.println("Enter Server's port number: ");
		String portNumber = reader.nextLine();
		System.out.println("Enter Client's private key: ");
		String cPrivateKey = reader.nextLine();
		System.out.println("Enter Server's public key: ");
		String sPublicKey = reader.nextLine();
		
		SecureRandom random = new SecureRandom();
		byte[] AESKey = new byte[16];
		random.nextBytes(AESKey);		
		byte[] signature = GetSignature(cPrivateKey, AESKey);
		byte[] ciphertxt = encryption(sPublicKey, AESKey);		
		ObjectClient message = new ObjectClient(ciphertxt, signature);
		System.out.println("ciphertext: " + Base64.getEncoder().encodeToString(message.cipher));
        System.out.println("signature: " + Base64.getEncoder().encodeToString(message. message));
		
        Socket clientSocket = new Socket(ip, Integer.parseInt(portNumber));
		ObjectOutputStream outToServer = new ObjectOutputStream(clientSocket.getOutputStream());
		outToServer.writeObject(message);
		ObjectInputStream inFromServer = new ObjectInputStream(clientSocket.getInputStream());
		ObjectServer received = (ObjectServer) inFromServer.readObject();

		clientSocket.close();
		String initial = "encrypt";
	    IvParameterSpec iv = new IvParameterSpec(initial.getBytes());
		SecretKeySpec serverkeySpec = new SecretKeySpec(AESKey, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, serverkeySpec, iv);
		byte[] decryptPlainByte = cipher.doFinal(received.cipher);
        SecretKey key = new SecretKeySpec(AESKey, 0, AESKey.length, "AES");
     
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
    
        byte[] generatedMac = mac.doFinal(decryptPlainByte);
		if (Arrays.equals(generatedMac, received.mac)){
			String mre = new String(decryptPlainByte);
			System.out.println("Received plain text: "+mre);
		}
		else{
			System.out.println("An error occurred!");
		}

	}
}

