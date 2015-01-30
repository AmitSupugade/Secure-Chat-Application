import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public class SecureChatClient extends helpers{
	static DatagramSocket socket;
	static int serverPort = 6060;
	static String serverAddress = "127.0.0.1";
	static InetAddress serverAddr = null;
	static DatagramPacket packetReceived;
	static InetAddress serverIP = null;
	static final int L1 = (int)Math.random() *1024;
	static final int MAX_UDP = 65507;
	static String username = new String();
	static String password = "Kumar";
	static boolean IaskedToConnect = false;
	static PrivateKey myTempDhPrivate = null;
	static String incorrect = "INCORRECT";
	static boolean receive = false;
	static String myPublic = new String();
	static String myPrivate = new String();
	static SecretKey Kme_s;
	static int count = 0;
	static boolean shouldAccept = true;
	
	static Thread sender = null;
	static Thread receiver = null;
	//static Thread receiveChat = null;
	static Thread sendChat = null;
	static String type = new String();
	
	static ArrayList<clientDatabase> Clist =new ArrayList<clientDatabase>(); 
	static ArrayList<String> OnlineUsers = new ArrayList<String>(); 
	
	static SecureChatClient client = new SecureChatClient();
	static RSAKeyGen RSAKeyGenerator = new RSAKeyGen();
	public static void main(String[] args)throws Exception{
		
		
		/*if(args.length != 2) {
        	System.out.println("Insufficient input args");
        	return;
    	} 
    	else if(args[0].length() == 0 || args[1].length() == 0) {
        	System.out.println("incorrect input values");
        	return;
    	}
 
		serverAddress = args[0];
 		serverPort = Integer.parseInt(args[1]);*/
		
		if(args.length != 1) {
        	System.out.println("Insufficient input args");
        	return;
    	} 
		type = args[0];
		
		socket = new DatagramSocket();
		serverIP = InetAddress.getByName(serverAddress);
		

		
		client.enterUsername();
		RSAKeyGenerator.generateKey(username);
		
		myPublic = username + "_Public.der";
		myPrivate = username + "_Private.der";
		
		client.loginProcess();
		client.getList();
		
		if(type.equals("I")){
			client.keepRunningSend();
		}
		else if(type.equals("A")){
			client.keepRunningReceive();
		}
		else{
			System.out.println("Incorrect Argument");
			System.exit(1);
		}
		
	}
	
	public void enterUsername()throws Exception{
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter your Username: ");
		username = br.readLine().toString();
	}
	
	public void enterPassword()throws Exception{
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter your Password: ");
		password = br.readLine().toString();
	}


	public void keepRunningReceive()throws Exception{
		System.out.println("Waiting to receive Packet");
		DatagramPacket chat_Req = receivePacket();
		String other_username = Iinitiatednot(chat_Req);
		
		receiver = new Thread(new DataReceive(other_username));
		receiver.start();
		
		sender = new Thread(new DataSend(other_username));
		sender.start();
		
	}
	
	
	
	public void keepRunningSend()throws Exception{
		String message = new String();
		while(true){
			System.out.println("Enter your message: " );
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			message = br.readLine();
			if(message.equals(list))
			{
				client.getList();
				continue;
			}
			else if(message.equals(connect))
			{
				chatManagement();
				break;
			}
			else if(message.equals(logout)){
				client.logoutManagement();
				break;
			}
		}
	}

	
	public boolean serverMessage(byte[] messageByte){
		boolean status = false;
		String message = new String(messageByte);
		if(message.equals("Incorrect Username")){
			System.out.println("You are not signed up on server");
			status = true;
		}
		else if(message.equals("Incorrect Password")){
			System.out.println("You have entered Incorrect Password");
			status = true;
		}
		return status;
	}
	

	
	public void logoutManagement() throws Exception{
		byte[] N4_before = logout_Req();
		String N4_Bef = new String(N4_before);
		
		DatagramPacket logout_Ack = receivePacket();
		Received_logoutResponse(logout_Ack);
		
	}
		public void Received_logoutResponse(DatagramPacket logout_Ack)throws Exception{
			byte[] encrypted = logout_Ack.getData();
			
			ByteBuffer buff = ByteBuffer.wrap(encrypted);
			
			int N4_len = buff.getInt();
			byte[] N4 = new byte[N4_len];
			buff.get(N4, 0, N4_len);
			
			String N4_lat = new String(N4);
			
			Kme_s = null;
			
			//if (N4_Bef.equals(N4_lat))
			System.out.println("LOGGED OUT SUCCESSFULLY ON SERVER");
			
			System.exit(1);
		}
		
	
	
	
	public byte[] logout_Req()throws Exception{
		byte[] N4 = GenerateNonce();
		byte[] uname = username.getBytes();
		
		byte[] buff_size = new byte[4*2 + N4.length + uname.length];
		ByteBuffer buff_1 = ByteBuffer.wrap(buff_size);
		
		buff_1.putInt(N4.length);
		buff_1.put(N4);
		buff_1.putInt(uname.length);
		buff_1.put(uname);
		
		byte[] toEncrypt = buff_1.array();
		byte[] logoutReq_1 = symmetricEncryption(toEncrypt, Kme_s);
		
		byte[] buff_size_2 = new byte[4*2 + logout.length() + logoutReq_1.length];
		ByteBuffer buff_2 = ByteBuffer.wrap(buff_size_2);

		buff_2.putInt(logout.length());
		buff_2.put(logout.getBytes());
		buff_2.putInt(logoutReq_1.length);
		buff_2.put(logoutReq_1);
		
		byte[] logoutReq = buff_2.array();
		sendPacket(logoutReq, serverIP, serverPort);
		System.out.println("LOGOUT REQUEST SENT");
		
		return N4;
		
	}
	

	
	public void getList()throws Exception{
		list_Req();
		receive = true;
		DatagramPacket list_Res = receivePacket();
		byte[] list_ResData = list_Res.getData();
		receive = false;
		byte[] decrypted = symmetricDecryption(list_ResData, Kme_s);
		ByteBuffer byteArray_req_1 = ByteBuffer.wrap(decrypted);
		
		int N5_length = byteArray_req_1.getInt();
      	byte[] N5 = new byte[N5_length];
        byteArray_req_1.get(N5, 0, N5_length);
        
        int arrayBytes_length = byteArray_req_1.getInt();
      	byte[] arrayBytes = new byte[arrayBytes_length];
        byteArray_req_1.get(arrayBytes, 0, arrayBytes_length);

        ByteBuffer buff2 = ByteBuffer.wrap(arrayBytes);
        
        int Number = buff2.getInt();
        
        OnlineUsers = new ArrayList<String>(); 
        for(int i=0; i < Number; i++){
        	int length = buff2.getInt();
          	byte[] uname = new byte[length];
            buff2.get(uname, 0, length);
            String userName = new String(uname);
            userName = userName.trim();
            OnlineUsers.add(userName);
        }
        for(int j=0; j< OnlineUsers.size(); j++)
        	System.out.println(OnlineUsers.get(j));
        
	}
	
	
	public void list_Req()throws Exception{
		byte[] N5 = GenerateNonce();
		byte[] encrypted = symmetricEncryption(N5, Kme_s);
		byte[] list_Req_size = new byte[4*2 + list.length() + encrypted.length];
		ByteBuffer list_req = ByteBuffer.wrap(list_Req_size);
		
		list_req.putInt(list.length());
		list_req.put(list.getBytes());
		list_req.putInt(encrypted.length);
		list_req.put(encrypted);
		
		byte[] list_Request = list_req.array();
		sendPacket(list_Request, serverIP, serverPort);
		System.out.println("LIST REQUEST SENT");
	}
	
	
	public String Iinitiatednot(DatagramPacket chat_Request)throws Exception{
		
		SecretKey KwithClient = null;

		System.out.println("CHAT REQUEST RECEIVED");

		byte[] combined = chat_Res(chat_Request.getData());
		System.out.println("CHAT RESPONSE SENT");

		ByteBuffer buff = ByteBuffer.wrap(combined);
		int N4bef_length = buff.getInt();
      	byte[] N4bef = new byte[N4bef_length];
        buff.get(N4bef, 0, N4bef_length);
		
        int uname_length = buff.getInt();
      	byte[] uname = new byte[uname_length];
        buff.get(uname, 0, uname_length);
        
        
        String other_username = new String(uname);

		DatagramPacket chat_Ack = receivePacket();
		byte[] receivedAck = chat_Ack.getData();
		System.out.println("CHAT ACK RECEIVED");
		buff = ByteBuffer.wrap(receivedAck);
		
		int N4_length = buff.getInt();
      	byte[] N4 = new byte[N4_length];
        buff.get(N4, 0, N4_length); 
        
        for (int i=0; i<Clist.size(); i++){
			if(Clist.get(i).name.equals(other_username)){
				KwithClient = Clist.get(i).sKey;
			}
		}
		
		byte[] N4Decrypted = symmetricDecryption(N4, KwithClient);
		
		if(new String(N4Decrypted).equals(new String(N4bef))){
			System.out.println("You are connected to -  " + other_username + ". Now, You can Chat");
			
		}
		
		return other_username;
	}
	

	public byte[] chat_Res(byte[] chat_Req)throws Exception{
		InetAddress IPAddress = null;
		int portNumber = 0;
		ByteBuffer byteArray_req_1 = ByteBuffer.wrap(chat_Req);
		
		int keyWord_length = byteArray_req_1.getInt();
      	byte[] keyWord = new byte[keyWord_length];
        byteArray_req_1.get(keyWord, 0, keyWord_length);
        
        int encrypted_length = byteArray_req_1.getInt();
      	byte[] encrypted = new byte[encrypted_length];
        byteArray_req_1.get(encrypted, 0, encrypted_length);
        
        byte[] myPrivateKey = readFromFile(myPrivate);
        byte[] decrypted = asymmetricDecryption(encrypted, myPrivateKey);
        
        ByteBuffer byteArray_req_2 = ByteBuffer.wrap(decrypted);
        
        int N2_length = byteArray_req_2.getInt();
      	byte[] N2 = new byte[N2_length];
        byteArray_req_2.get(N2, 0, N2_length);
        
        int othersuname_length = byteArray_req_2.getInt();
      	byte[] othersuname = new byte[othersuname_length];
        byteArray_req_2.get(othersuname, 0, othersuname_length);
        String othersUsername = new String(othersuname);
        othersUsername = othersUsername.trim();
        
        int othersDHPublic_length = byteArray_req_2.getInt();
      	byte[] othersDHPublic = new byte[othersDHPublic_length];
        byteArray_req_2.get(othersDHPublic, 0, othersDHPublic_length);
        
        connectTo(othersUsername);
        
        //Create chat response
        byte[] N4 = GenerateNonce();
        
        KeyPair myDHPair = DHPublicKeyGenerator(P, G, L1);
        byte[] myDHPublicKey = myDHPair.getPublic().getEncoded();
        
        SecretKey Kme_other = DHSharedKeyGenerator(othersDHPublic, myDHPair.getPrivate());
        
        for (int i=0; i<Clist.size(); i++){
			if(Clist.get(i).name.equals(othersUsername)){
				Clist.get(i).sKey = Kme_other;
			}
		}
        
        byte[] chat_Res1_size = new byte[4*4 + N2.length + N4.length + username.getBytes().length + myDHPublicKey.length];
		ByteBuffer chat_Res_1 = ByteBuffer.wrap(chat_Res1_size);
		
		chat_Res_1.putInt(N2.length);
		chat_Res_1.put(N2);
		
		chat_Res_1.putInt(N4.length);
		chat_Res_1.put(N4);
		
		chat_Res_1.putInt(username.getBytes().length);
		chat_Res_1.put(username.getBytes());
		
		chat_Res_1.putInt(myDHPublicKey.length);
		chat_Res_1.put(myDHPublicKey);
		
		byte[] forEncryption = chat_Res_1.array();
		
		String otherPublicKeyFile = othersUsername + "_Public.der";

		byte[] otherPublicKey = readFromFile(otherPublicKeyFile);
		
		byte[] chat_Res_Encrypted = asymmetricEncryption(forEncryption, otherPublicKey);
		
		 for (int i=0; i<Clist.size(); i++){
				if(Clist.get(i).name.equals(othersUsername)){
					IPAddress = Clist.get(i).IPAdrr;
					portNumber = Clist.get(i).port_num;
				}
			}
		
		 sendPacket(chat_Res_Encrypted , IPAddress, portNumber);
		byte[] toReturn_size = new byte[4*2 + N4.length + othersUsername.length()];
		ByteBuffer toReturn = ByteBuffer.wrap(toReturn_size);
		
		toReturn.putInt(N4.length);
		toReturn.put(N4);
		toReturn.putInt(othersUsername.length());
		toReturn.put(othersUsername.getBytes());
		
		byte[] toReturnByte = toReturn.array();
		return toReturnByte;
	}
	
	
	public void chatManagement()throws Exception{
			Iinitiated();
	}

	
	public void Iinitiated()throws Exception{
		
		int flag = 0;
		String other_user = new String();
		
		while(flag == 0){
			System.out.println("Enter username you want to connect to: ");
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			other_user = br.readLine().toString();
			
			for (int i=0; i<OnlineUsers.size(); i++){
				String toSee = new String(OnlineUsers.get(i));
				if(toSee.equals(other_user)){
					flag = 1;
				break;	
				}
			}
			
			if(flag == 0){
				System.out.println("User is not online. Enter another username");
			}
		}

		
		connectTo(other_user);
		
		chat_Req(other_user);
		System.out.println("CHAT REQUEST SENT");

		DatagramPacket Rec_Response = receivePacket();
		System.out.println("Packet Received");
		byte[] N4 = Received_chatRes(Rec_Response);
		System.out.println("CHAT RESPONSE RECEIVED");
		
		chat_Ack(N4, other_user);
		System.out.println("CHAT ACK SENT");
		System.out.println("You are connected to -  " + other_user + ". Now, You can Chat");
		
		receiver = new Thread(new DataReceive(other_user));
		receiver.start();
		
		sender = new Thread(new DataSend(other_user));
		sender.start();
	}

	
	public void chat_Ack(byte[] N4, String other_user)throws Exception{
		SecretKey KwithClient = null;
		InetAddress IPAddress = null;
		int portNumber = 0;
		
		for (int i=0; i<Clist.size(); i++){
			if(Clist.get(i).name.equals(other_user)){
				KwithClient = Clist.get(i).sKey;
				IPAddress = Clist.get(i).IPAdrr;
				portNumber = Clist.get(i).port_num;
			}
		}
		
		byte[] chatAck_1 = symmetricEncryption(N4, KwithClient);
		
		byte[] buff_1_size = new byte[4 + chatAck_1.length];
		ByteBuffer buff_1 = ByteBuffer.wrap(buff_1_size);
		
		buff_1.putInt(chatAck_1.length);
		buff_1.put(chatAck_1);
		
		byte[] chatAck = buff_1.array();
		sendPacket(chatAck, IPAddress, portNumber);
		
	}
	
	
	public byte[] Received_chatRes(DatagramPacket received_chatResp)throws Exception{
		
		byte[] myPrivateKey = readFromFile(myPrivate);
		
		byte[] encrypted = received_chatResp.getData();
		byte[] decrypted = asymmetricDecryption(encrypted, myPrivateKey);
		
		ByteBuffer buff = ByteBuffer.wrap(decrypted);
	        
	    int N2_length = buff.getInt();
	    byte[] N2 = new byte[N2_length];
	    buff.get(N2, 0, N2_length);
	    
	    int N4_length = buff.getInt();
	    byte[] N4 = new byte[N4_length];
	    buff.get(N4, 0, N4_length);
	    
	    int uname_length = buff.getInt();
	    byte[] uname = new byte[uname_length];
	    buff.get(uname, 0, uname_length);
	    
	    String userName = new String(uname);
	    userName = userName.trim();
	    
	    int DHPublic_length = buff.getInt();
	    byte[] DHPublic = new byte[DHPublic_length];
	    buff.get(DHPublic, 0, DHPublic_length);
	    
	    SecretKey Kme_other = DHSharedKeyGenerator(DHPublic, myTempDhPrivate);
        myTempDhPrivate = null;
        for (int i=0; i<Clist.size(); i++){
			if(Clist.get(i).name.equals(userName)){
				Clist.get(i).sKey = Kme_other;
			}
		}
	    
	    return N4;
	}
	
	public void chat_Req(String other_user)throws Exception{
		byte[] chatReq = null;
		InetAddress IP_otherClient = null;
		int port_otherClient = 0;

        //Prepare Chat Request
        byte[] N2 = GenerateNonce();
        
        KeyPair myDHPairClient = DHPublicKeyGenerator(P, G, L1);
        byte[] DHPublicKey = myDHPairClient.getPublic().getEncoded();
        myTempDhPrivate = myDHPairClient.getPrivate();
        
        byte[] chat_Req1_size = new byte[4*3 + N2.length + username.getBytes().length + DHPublicKey.length];
		ByteBuffer chat_Req_1 = ByteBuffer.wrap(chat_Req1_size);
		
		chat_Req_1.putInt(N2.length);
		chat_Req_1.put(N2);
		chat_Req_1.putInt(username.getBytes().length);
		chat_Req_1.put(username.getBytes());
		chat_Req_1.putInt(DHPublicKey.length);
		chat_Req_1.put(DHPublicKey);
		
		byte[] toEncrypt = chat_Req_1.array();
		
		String othersPublic = other_user + "_Public.der";
		byte[] othersPublicKey = readFromFile(othersPublic);
		byte[] chat_Req1 = asymmetricEncryption(toEncrypt, othersPublicKey);
		
		byte[] chat_Req_size = new byte[4*2 + chat.getBytes().length + chat_Req1.length];
		ByteBuffer chat_Req_Buffer = ByteBuffer.wrap(chat_Req_size);
		
		chat_Req_Buffer.putInt(chat.getBytes().length);
		chat_Req_Buffer.put(chat.getBytes());
		chat_Req_Buffer.putInt(chat_Req1.length);
		chat_Req_Buffer.put(chat_Req1);
		
		chatReq = chat_Req_Buffer.array();
		
		for (int i=0; i<Clist.size(); i++){
			if(Clist.get(i).name.equals(other_user)){
				IP_otherClient = Clist.get(i).IPAdrr;
				port_otherClient = Clist.get(i).port_num;
			}
		}

		sendPacket(chatReq, IP_otherClient, port_otherClient);

	}
	
	public void connectTo(String other_username)throws Exception{
		System.out.println("Connect Statement 1 other username" + other_username);
		byte[] userConnect = connect_Req(other_username);
		
		System.out.println("CONNECT REQUEST SENT to connect to" + new String(userConnect));
		
		DatagramPacket connect_Response = receivePacket();
        
		System.out.println("CONNECT RESPONSE RECEIVED");
		byte[] connect_ResponseData = connect_Response.getData();
		connRes_Received(connect_ResponseData, userConnect);

	}
	

	 public void connRes_Received(byte[] connectRes, byte[] userToConnect)throws Exception{
			byte[] decrypted = symmetricDecryption(connectRes, Kme_s);
			
			ByteBuffer byteArray_req_1 = ByteBuffer.wrap(decrypted);
			
			int N1_length = byteArray_req_1.getInt();
	      	byte[] N1 = new byte[N1_length];
	        byteArray_req_1.get(N1, 0, N1_length);
	        
	        int RSAKeyOtherClient_length = byteArray_req_1.getInt();
	      	byte[] RSAKeyOtherClient = new byte[RSAKeyOtherClient_length];
	        byteArray_req_1.get(RSAKeyOtherClient, 0, RSAKeyOtherClient_length);
	        
	        String Filename = new String(userToConnect) + "_Public.der";
	        writeToFile(Filename, RSAKeyOtherClient);
	        
	        int IPAddressBytes_length = byteArray_req_1.getInt();
	      	byte[] IPAddressBytes = new byte[IPAddressBytes_length];
	        byteArray_req_1.get(IPAddressBytes, 0, IPAddressBytes_length);
	        InetAddress IP_otherClient = InetAddress.getByAddress(IPAddressBytes);
	        int port_otherClient = byteArray_req_1.getInt();
	        
	        System.out.println(new String(userToConnect) + "IP = " + IP_otherClient.toString());
	        System.out.println(new String(userToConnect) + "Port = " + port_otherClient);
	       
	        String userConnect = new String(userToConnect);
	        
	        for (int i=0; i<Clist.size(); i++){
				if(Clist.get(i).name.equals(userConnect)){
					Clist.get(i).IPAdrr = IP_otherClient;
					Clist.get(i).port_num = port_otherClient;
				}
			}
	 }
	
	 
	public byte[] connect_Req(String userToConnect)throws Exception{
		byte[] N1 = GenerateNonce();
		
		byte[] userConnect = userToConnect.getBytes();
		
		byte[] toEncrypt = new byte[4*2 + N1.length + userConnect.length]; 
		ByteBuffer byteArray_conReq = ByteBuffer.wrap(toEncrypt);
		System.out.println(N1.length);
		byteArray_conReq.putInt(N1.length);
		byteArray_conReq.put(N1);
		byteArray_conReq.putInt(userConnect.length);
		byteArray_conReq.put(userConnect);
		
		
		//Add to client's database
        clientDatabase newClient = new clientDatabase();
        newClient.name = userToConnect;
        newClient.IPAdrr = null;
        newClient.port_num = 0;
        Clist.add(newClient);
        
        
		byte[] forEncryption = byteArray_conReq.array();
		byte[] encrypted = symmetricEncryption(forEncryption, Kme_s);
	
		byte[] conReq = new byte[4*2 + connect.length() + encrypted.length];
		ByteBuffer connect_Req = ByteBuffer.wrap(conReq);
		
		connect_Req.putInt(connect.getBytes().length);
		connect_Req.put(connect.getBytes());
		connect_Req.putInt(encrypted.length);
		connect_Req.put(encrypted);
		
		byte[] connect_Req_Byte = connect_Req.array();
		sendPacket(connect_Req_Byte, serverIP, serverPort);
		
		return userConnect;
	}

	
	public void loginProcess()throws Exception{
		if(username.equals("wrong")){
			enterUsername();
			enterPassword();

			RSAKeyGenerator.generateKey(username);
		}
		else{

			enterPassword();
		}

		
		byte[] login_req = loginReq();
		sendPacket(login_req, serverIP, serverPort);
		System.out.println("LOGIN REQUEST SENT");
		
		DatagramPacket login_res = receivePacket();
		byte[] loginRes = login_res.getData();
		System.out.println("LOGIN RESPONSE RECEIVED");
		
		byte[] login_ver = loginVerify(loginRes);
		String toCompare = new String(login_ver);
		
		if(toCompare.equals(incorrect) && count<2){
			System.out.println("Incorrect Username. Enter Correct username and Password Again.");
			count++;
			username = "wrong";
			loginProcess();
		}
		
		System.out.println(count);
		if(count == 2){
			count = 0;
			System.out.println("Maximum Attempts reached. Exiting");
			System.exit(1);
		}

		sendPacket(login_ver, serverIP, serverPort);
		System.out.println("LOGIN VERIFY SENT");
		
		DatagramPacket login_ack = receivePacket();
		System.out.println("LOGIN ACK RECEIVED");
		
		byte[] loginAck = login_ack.getData();
		byte[] login_Ack = symmetricDecryption(loginAck, Kme_s);
		
		ByteBuffer buff = ByteBuffer.wrap(login_Ack);
		
		int N3_length = buff.getInt();
		byte[] N3_Rec = new byte[N3_length];
		buff.get(N3_Rec, 0, N3_length);

		String tocheck = "Incorrect Password";
		String recCheck = new String(N3_Rec);
		
		String incorrectPwd = "Incorrect Password";
		if(recCheck.equals(incorrectPwd) && count<2){
			System.out.println("Incorrect Password. Enter Correct username and Password Again.");
			count++;
			loginProcess();
		}
		
		System.out.println(count);
		if(count == 2){
			count = 0;
			System.out.println("Maximum Attempts reached. Exiting");
			System.exit(1);
		}
	}
	
	public byte[] loginVerify(byte[] loginRes)throws Exception{
		
		String myPrivate = username + "_Private.der";
		byte[] keyBytes = readFromFile(myPrivate);
		byte[] login_Res = asymmetricDecryption(loginRes, keyBytes);
		
		ByteBuffer byteArray_res = ByteBuffer.wrap(login_Res);
		
		int N1_length = byteArray_res.getInt();
      	byte[] N1 = new byte[N1_length];
        byteArray_res.get(N1, 0, N1_length);
        
        boolean status = serverMessage(N1);
        if(status){
        	return incorrect.getBytes();
        }
        
        int N2_length = byteArray_res.getInt();
      	byte[] N2 = new byte[N2_length];
        byteArray_res.get(N2, 0, N2_length);
        
        int sa_length = byteArray_res.getInt();
      	byte[] sa = new byte[sa_length];
        byteArray_res.get(sa, 0, sa_length);
        
        int serverDHPublic_length = byteArray_res.getInt();
      	byte[] serverDHPublic = new byte[serverDHPublic_length];
      	byteArray_res.get(serverDHPublic, 0, serverDHPublic_length);
        
        int R_length = byteArray_res.getInt();
      	byte[] R = new byte[R_length];
        byteArray_res.get(R, 0, R_length);
        
        byte[] N3 = GenerateNonce();
    	
        KeyPair myDHPair = DHPublicKeyGenerator(P, G, L1);
        PrivateKey myDHPrivateKey = myDHPair.getPrivate();
        byte[] DHPublicKey = myDHPair.getPublic().getEncoded();
        
        Kme_s = DHSharedKeyGenerator(serverDHPublic, myDHPrivateKey);
        
		byte[] hash_1 = generateHash(password, sa);
		
		String Rstrng = new String(R);

		byte[] hash = generateHash(Rstrng, hash_1);
		
		byte[] loginVer_length = new byte[4*4 + N2.length + N3.length + hash.length + DHPublicKey.length];
		ByteBuffer loginVer = ByteBuffer.wrap(loginVer_length);
		
		loginVer.putInt(N2.length);
		loginVer.put(N2);
		loginVer.putInt(N3.length);
		loginVer.put(N3);
		loginVer.putInt(hash.length);
		loginVer.put(hash);
		loginVer.putInt(DHPublicKey.length);
		loginVer.put(DHPublicKey);
		
		byte[] PublickeyBytes = readFromFile("server_Public.der");
		byte[] login_Ver = asymmetricEncryption(loginVer.array(), PublickeyBytes);

		return login_Ver;
	}
	
	public byte[] loginReq()throws Exception{
		byte[] login_req = null;
		
		byte[] N1 = GenerateNonce();
				
		String myPublic = username + "_Public.der";
		byte[] myPublicKey = readFromFile(myPublic);
		
		byte[] keyBytes = new byte[4*3 + N1.length + username.length() +myPublicKey.length];
		ByteBuffer byteArray = ByteBuffer.wrap(keyBytes);
		
		byte[] uname = username.getBytes();
		
		byteArray.putInt(N1.length);
		byteArray.put(N1);
		byteArray.putInt(uname.length);
		byteArray.put(uname);
		byteArray.putInt(myPublicKey.length);
		byteArray.put(myPublicKey);
		
		
		byte[] toEncrypt = byteArray.array();
		
		byte[] PublickeyBytes = readFromFile("server_Public.der");
		byte[] encrypted = asymmetricEncryption(toEncrypt, PublickeyBytes);
		
		byte[] login_one_bytes = new byte[4*2 + login.length() + encrypted.length];
		ByteBuffer login_one = ByteBuffer.wrap(login_one_bytes);

		login_one.putInt(login.length());
		login_one.put(login.getBytes());
		login_one.putInt(encrypted.length);
		login_one.put(encrypted);
		
		login_req = login_one.array();

		return login_req;
	}
	
	public void sendPacket(byte[] dataToSend, InetAddress IPAddress, int port)throws Exception{

		DatagramPacket sendPacket = new DatagramPacket(dataToSend, dataToSend.length, IPAddress, port);
		socket.send(sendPacket);
	}
	
	public DatagramPacket receivePacket()throws Exception{
		packetReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
		socket.receive(packetReceived);
		return packetReceived;
	}
	
	

	static class chatReceive implements Runnable{
		
		public void run(){
			try{
				client.keepRunningReceive();
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
	}
	
	static class chatSend implements Runnable{
		
		public void run(){
			try{
				client.keepRunningSend();
			}
			catch(Exception e){
				e.printStackTrace();
			}
		
		}
	}
	
	
	
	static class DataSend implements Runnable{

	String other_user = new String();
		
		public DataSend(String user){
			this.other_user = user;
		}
	
		public void run() {
			String message = new String();
			InetAddress IPAddress = null;
			int portNumber = 0;
	
			while(true){
				try {
					System.out.println("Enter your message for " + other_user +" : " );
					BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
					message = br.readLine();
					try{
					if(message.equals(list))
					{
						client.getList();
						continue;
					}
					else if(message.equals(connect))
					{
						shouldAccept = false;
						receiver.interrupt();
						client.chatManagement();
						continue;
					}
					else if(message.equals(logout)){
						client.logoutManagement();
						break;
					}
					}
					catch(Exception e){
						e.printStackTrace();
					}
				
				byte[] privateKey = readFromFile(myPrivate);
				byte[] messageHMAC = generateHMAC(message.getBytes(), privateKey);
				
				byte[] msg_size = new byte[4*2 + messageHMAC.length + message.length()];
				ByteBuffer buff = ByteBuffer.wrap(msg_size);
				
				buff.putInt(messageHMAC.length);
				buff.put(messageHMAC);
				buff.putInt(message.length());
				buff.put(message.getBytes());
				
				byte[] data = buff.array();
				
				
				 for (int i=0; i<Clist.size(); i++){
						if(Clist.get(i).name.equals(other_user)){
							IPAddress = Clist.get(i).IPAdrr;
							portNumber = Clist.get(i).port_num;
						}
					}
				 
				if(message != null){
					DatagramPacket sendPacket = new DatagramPacket(data, data.length, IPAddress, portNumber);
					socket.send(sendPacket);
					System.out.println("Data Sent");
				}
				}
				catch(IOException ex){
					ex.printStackTrace();
				}
			}
		}
	}
	

	static class DataReceive implements Runnable{
		String other_user = new String();
		
		public DataReceive(String user){
			this.other_user = user;
		}
		
		public void run(){
			while(true){
				try{
					String data = new String();
					ByteBuffer buff = null;
				
					DatagramPacket pcktReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
					socket.receive(pcktReceived);
					byte[] receivedData= pcktReceived.getData();
					
					buff = ByteBuffer.wrap(receivedData);

					int messageHMAC_length = buff.getInt();
			      	byte[] messageHMAC = new byte[messageHMAC_length];
			        buff.get(messageHMAC, 0, messageHMAC_length);
			        
			        String toCheck = new String(messageHMAC);
			        toCheck = toCheck.trim();
			        
			        if(toCheck.equals(logout)){
			        	client.Received_logoutResponse(pcktReceived);
			        	break;
			        }
			        else{
			        	int message_length = buff.getInt();
			        	byte[] message = new byte[message_length];
			        	buff.get(message, 0, message_length);
			        	
			        	String fileName = other_user + "_Public.der";
			        	byte[] publicKey = readFromFile(fileName);
			        	boolean status = HMACverify(message, messageHMAC, publicKey);
			        	
			        	if (status == true){
			        		data = new String (message);
			        		data = data.trim();
			        		System.out.println("Data received: "+ data);
			        	}
			        	
			        	else{
			        		System.out.println("Data has been changed. HMAC is not matching");
			        	}
			        
			        }

				}
				catch(Exception ex){
					ex.printStackTrace();
				}
			}
		}
	}
}
