import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

//import sun.security.provider.SecureRandom;


public class helpers {
	static int SYMMETRIC_KEY_SIZE = 128;
	static int ASYMMETRIC_KEY_SIZE = 2048;
	static final int MAX_UDP = 65507;
	static String login = "LOGIN";
	static String connect = "CONNECT";
	static String chat = "CHAT";
	static String list = "LIST";
	static String logout = "LOGOUT";
	static final BigInteger P = new BigInteger(
			"118539106163103455536379147004961367288843953236491023527594295060060859680741589469770990497791240951568655167946823593107118424420940518582947778487487989116692658067363411263318937721491573236667816363175510013718506361043376316374497960667110912165612271045737683283219912755118746405028518492721139034801");
	static final BigInteger G = new BigInteger(
			"66769902729453773529591131231569572102735544195993481143033457484815030002596316655928306151074126943049377614450028533734323959138888686552706761807171386969245696096129361633104534226150835208919251885611066228846063597270995942371116296807245855582424161473422149566011004210899105193304176803779403265090");
	
	
	/*public void sendPacket(DatagramSocket socket, byte[] dataToSend, SocketAddress destinationAddress)throws Exception{
		//InetAddress IPaddress = SAddress.getAddress();
		//int port = SAddress.getPort();
		DatagramPacket sendPacket = new DatagramPacket(dataToSend, dataToSend.length, destinationAddress);
		socket.send(sendPacket);
	}
	
	public DatagramPacket receivePacket(DatagramSocket socket)throws Exception{
		packetReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
		socket.receive(packetReceived);
		//byte[] receivedData = packetReceived.getData();
		//SocketAddress receivedFrom = packetReceived.getSocketAddress();
		return packetReceived;
	}*/
	
	//Generate Nonce
	public byte[] GenerateNonce()throws Exception{
		Random random = SecureRandom.getInstance("SHA1PRNG");
		byte[] nonce = new byte[16];
		random.nextBytes(nonce);
		return nonce;
	}
	
	//Generate Hash of given data
	/*public byte[] generateHash(byte[] toHash)throws Exception{
		MessageDigest digest = MessageDigest.getInstance("SHA-512"); 
		digest.update(toHash); 
		byte[] hashed = digest.digest();
		return hashed;
	}*/
	
	public static byte[] generateHash(String pass, byte[] salt) throws GeneralSecurityException {
		   char[] password = pass.toCharArray();
		   PBEKeySpec spec = new PBEKeySpec(password, salt, 200, SYMMETRIC_KEY_SIZE);
		   SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		   return factory.generateSecret(spec).getEncoded();
		  }
	
	public static boolean matches(String password, byte[] hash, byte[] salt) 
		   throws GeneralSecurityException {
		   return Arrays.equals(hash, generateHash(password, salt));
		  }

	
	//Diffie-Hellman public Key Generation
		public KeyPair DHPublicKeyGenerator(BigInteger p, BigInteger g, int l) throws Exception {
				KeyPairGenerator kgen = KeyPairGenerator.getInstance("DH");
				DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
				kgen.initialize(dhSpec);
				KeyPair keypair = kgen.generateKeyPair();
				return keypair;
		}

		//Generate Diffie-Hellman Secret Key
		public SecretKey DHSharedKeyGenerator(byte[] pubkeybytes, PrivateKey pvtkey) throws Exception {
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubkeybytes);
				KeyFactory keyFact = KeyFactory.getInstance("DH");
				PublicKey pubkey = keyFact.generatePublic(x509KeySpec);
				KeyAgreement DHKeyAgreement = KeyAgreement.getInstance("DH");
				DHKeyAgreement.init(pvtkey);
				DHKeyAgreement.doPhase(pubkey, true);
				//SecretKey secretKey = ka.generateSecret("AES");
				SecretKey finalSharedsecret = new SecretKeySpec(DHKeyAgreement.generateSecret(), 0, SYMMETRIC_KEY_SIZE/8, "AES");
				return finalSharedsecret;
		}
	

    
	//Generate HMAC
	/*public static byte[] generateHMAC(SecretKey symmetricKey, byte[] toHash)throws Exception{
		SecretKeySpec specs = new SecretKeySpec(symmetricKey.getEncoded(), "SHA-512");
		Mac mac = Mac.getInstance("SHA-512");
		mac.init(specs);
		byte[] hashedMessage = mac.doFinal(toHash);
		return hashedMessage;
	}
	
	//Verify HMAC
	public static boolean verifyHMAC(SecretKey symmetricKey, byte[]hashedMessage, byte[] message)throws Exception{
		byte[] messageHMAC = generateHMAC(symmetricKey, message); 
		if(Arrays.equals(hashedMessage, messageHMAC)){
			return true;
		}
		else{
			return false;
		}
	}*/
		
		
		//Digitally signing the data
				public static byte[] generateHMAC(byte[] toSign, byte[] senderPrivateKey){
				    byte[] digitallySigned = null;
				    try{
						
				    	PKCS8EncodedKeySpec  privateKeySpec = new PKCS8EncodedKeySpec(senderPrivateKey);
				    	KeyFactory kfactory = KeyFactory.getInstance("RSA");
			            PrivateKey pkey = kfactory.generatePrivate(privateKeySpec);
			            
			            Signature dSign = Signature.getInstance("SHA1withRSA");
			            dSign.initSign(pkey);
			            dSign.update(toSign);
			            digitallySigned = dSign.sign();
			        }
				    catch(Exception ex){
				    	ex.printStackTrace();
				    }
				    return digitallySigned;
				}
				
				//Verifying the digitally signed data
				public static boolean HMACverify(byte[] toSign, byte[] signed, byte[] senderPublicKey){
				    boolean verified = false;
				    try{
						
					X509EncodedKeySpec  publicKeySpec = new X509EncodedKeySpec(senderPublicKey);
					KeyFactory kfactory = KeyFactory.getInstance("RSA");
			            	PublicKey pkey = kfactory.generatePublic(publicKeySpec);
			            
			            	Signature dSign = Signature.getInstance("SHA1withRSA");
			            	dSign.initVerify(pkey);
			            	dSign.update(toSign);
			            	verified = dSign.verify(signed);
				    }
				    catch(Exception ex){
					ex.printStackTrace();
				    }
				    return verified;
				}
				
		
    
	//Generation of symmetric Key
	private static SecretKey createSymmetricKey(){
		SecretKey symmetricKey = null;
	    try{
	    	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	    	keyGen.init(SYMMETRIC_KEY_SIZE);
	    	symmetricKey = keyGen.generateKey();
	    }
	    catch(Exception ex){
	    	ex.printStackTrace();
	    }
		return symmetricKey;
	}
			
	//Encryption with RSA
	public static byte[] asymmetricEncryption(byte[] toEncrypt, byte[] keyBytes){
		byte[] encrypted = null;
		try{
	    	SecretKey symmetricKey = createSymmetricKey();
	    	
			X509EncodedKeySpec  publicKeySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kfactory = KeyFactory.getInstance("RSA");
			PublicKey pkey = kfactory.generatePublic(publicKeySpec);
            
			Cipher descipher = Cipher.getInstance("RSA");
			descipher.init(Cipher.ENCRYPT_MODE, pkey);
			byte[] RSAencryptedKey = descipher.doFinal(symmetricKey.getEncoded());
			
			byte[] symmetricEncrypted = symmetricEncryption(toEncrypt, symmetricKey);
			
			//Combine encrypted symmetric key and encrypted plain text
			encrypted = new byte[ASYMMETRIC_KEY_SIZE / 8 + symmetricEncrypted.length];
			System.arraycopy(RSAencryptedKey, 0, encrypted, 0, ASYMMETRIC_KEY_SIZE / 8);
			System.arraycopy(symmetricEncrypted, 0, encrypted, ASYMMETRIC_KEY_SIZE / 8, symmetricEncrypted.length);
	    }
	    catch(Exception ex){
		ex.printStackTrace();
	    }
	    return encrypted;
	}
	
	// Decryption with RSA
	public static byte[] asymmetricDecryption(byte[] encrypted, byte[] keyBytes){
	    byte[] decrypted = null;
	    byte[] symmetricKeyBytes = new byte[ASYMMETRIC_KEY_SIZE / 8];
	    byte[] RSAencryptedKey = new byte[ASYMMETRIC_KEY_SIZE / 8];
	    byte[] symmetricEncrypted = new byte[encrypted.length - ASYMMETRIC_KEY_SIZE / 8];
	    
	    System.arraycopy(encrypted, 0, RSAencryptedKey, 0, ASYMMETRIC_KEY_SIZE / 8);
	    System.arraycopy(encrypted, ASYMMETRIC_KEY_SIZE / 8, symmetricEncrypted, 0, encrypted.length - ASYMMETRIC_KEY_SIZE / 8);
	    
	    try{
	    	PKCS8EncodedKeySpec  privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kfactory = KeyFactory.getInstance("RSA");
           	PrivateKey pkey = kfactory.generatePrivate(privateKeySpec);
            
            Cipher descipher = Cipher.getInstance("RSA");
            descipher.init(Cipher.DECRYPT_MODE, pkey);
            symmetricKeyBytes = descipher.doFinal(RSAencryptedKey);
            SecretKeySpec  symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
            
            decrypted = symmetricDecryption(symmetricEncrypted ,symmetricKey);
	    }
	    catch(Exception ex){
	    	ex.printStackTrace();
	    }
	    return decrypted;
	}
	
	//Encryption with AES
			public static byte[] symmetricEncryption(byte[] bytes, SecretKey sessionKey)throws Exception{
				 byte[] AESencrypted = null;
				    try{
				    	Cipher cf = Cipher.getInstance("AES/CTR/NoPadding");
			        	byte[] initializationVector = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
			        	IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
			        	cf.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);
						AESencrypted = cf.doFinal(bytes);
				    }
				    catch(Exception ex){
				    	ex.printStackTrace();
				    }
					return AESencrypted;
			}
			
			//Decryption with AES
			public static byte[] symmetricDecryption(byte[] bytes, SecretKey sessionKey)throws Exception{
				byte[] AESdecrypted = null;
			    try{
			    	Cipher cf = Cipher.getInstance("AES/CTR/NoPadding");
		        	byte[] initializationVector = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
		        	IvParameterSpec ivParaSpec = new IvParameterSpec(initializationVector);
		        	cf.init(Cipher.DECRYPT_MODE, sessionKey, ivParaSpec);
		        	AESdecrypted = cf.doFinal(bytes);
			    }
			    catch(Exception ex){
			    	ex.printStackTrace();
			    }
			    return AESdecrypted;
			}
			
	//Reading data from a file
	public static byte[] readFromFile(String file){
	    int length;
        byte []bytes = null;
        
        try 
        {
            File f = new File(file);
            FileInputStream filedata = new FileInputStream(f);
            DataInputStream indata = new DataInputStream(filedata);
            length = (int)f.length();
          
            if(length > 0)
            {
        	    bytes = new byte[length];
            } 
            else
            {
                System.out.println("Input file does not contain any data.");
            }
            
            indata.readFully(bytes);
            filedata.close();
            return bytes;
        }
        catch (Exception e)
        {
            e.printStackTrace();           
        }
        return bytes;
    }
	
	//Writing data to the file
    public static void writeToFile(String file, byte []bytes)
    {
        try 
        {
            DataOutputStream outfile = new DataOutputStream(new FileOutputStream(file)); 
            outfile.write(bytes);
            outfile.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();           
        }
        //return bytes.length;
    }
	
	public void sendData(DatagramSocket socket, byte[] data, InetAddress IPaddress, int port){
		try{
			DatagramPacket sendPacket = new DatagramPacket(data, data.length, IPaddress, port);
			socket.send(sendPacket);
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	
}
