import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.io.FileOutputStream;
import java.io.IOException;

public class AsymmetricKeyProducer {
	
	private static void generateKeys(String algorithm, int numberOfBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		
		KeyPairGenerator keyGenerater = KeyPairGenerator.getInstance(algorithm);
        keyGenerater.initialize(numberOfBits);
        KeyPair keyPair = keyGenerater.genKeyPair();
        PrivateKey privateKey1 = keyPair.getPrivate();
        PublicKey publicKey1 = keyPair.getPublic();
        
        byte[] privateKeyBytes = privateKey1.getEncoded();
        byte[] publicKeyBytes = publicKey1.getEncoded();
        
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
        
        Scanner reader = new Scanner(System.in);
		System.out.println("Enter file's path to store the public key: ");
		String publicPath = reader.nextLine();
		System.out.println("Enter the file's path to store the private key: ");
		String privatePath = reader.nextLine();
		reader.close();
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey2.getEncoded());
		FileOutputStream Public = new FileOutputStream(publicPath);
		Public.write(x509EncodedKeySpec.getEncoded());
		Public.close();
		
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey2.getEncoded());
		FileOutputStream Private = new FileOutputStream(privatePath);
		Private.write(pkcs8EncodedKeySpec.getEncoded());
		Private.close();
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		generateKeys("RSA",1024);
	}
}

