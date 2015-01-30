import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecureChatServer extends helpers{
	
	//Static Class VARIABLES
	static final int MAX_UDP = 65507;
	static DatagramSocket socket = null;
	static int port;
	static DatagramPacket packetReceived;
	static String messageData = null;
	static int loginAttempts = 0;
    KeyPair serverDHPair = null;
	
	static ClientList clist = new ClientList();
	static SecureChatServer SchatServer = new SecureChatServer();
	
	public static void main(String[] args)throws Exception{
	
		port = 6060;
		
		System.out.printf("Chat Server Initialized on port %d \n", port);
		socket = new DatagramSocket(port);
		
		
		SchatServer.database();
		
		//INITIATING THE SERVER RECIEVER THREAD
		Thread serverReceiver = new Thread(new ServerReceive());
		serverReceiver.start();
	}
	
	public void database()throws Exception{
		
		// USER NAME AND PASSWORD
		String user_1 = "Ishan";
		String passwd_1 = "Kumar";
		String user_2 = "Amit";
		String passwd_2 = "Supugade";
		String user_3 = "Guest";
		String passwd_3 = "Guest";
		
		//ITERATING TO SAVE SALT AND HASH IN DATABASE
		 for(int i=0;i<clist.Info_clients.size();i++){
				if(clist.Info_clients.get(i).name.equals(user_1)){
					byte[] sa = GenerateNonce();
					clist.Info_clients.get(i).salt = sa;
					byte[] hash_1 = generateHash(passwd_1, sa);
					clist.Info_clients.get(i).hash = hash_1;
				}
			}
		 
		 for(int i=0;i<clist.Info_clients.size();i++){
				if(clist.Info_clients.get(i).name.equals(user_2)){
					byte[] sa = GenerateNonce();
					clist.Info_clients.get(i).salt = sa;
					byte[] hash_2 = generateHash(passwd_2, sa);
					clist.Info_clients.get(i).hash = hash_2;
				}
			}
		 
		 for(int i=0;i<clist.Info_clients.size();i++){
				if(clist.Info_clients.get(i).name.equals(user_3)){
					byte[] sa = GenerateNonce();
					clist.Info_clients.get(i).salt = sa;
					byte[] hash_3 = generateHash(passwd_3, sa);
					clist.Info_clients.get(i).hash = hash_3;
				}
			}
	}
	

	
	
	/*public void keepRunning(){
		try{
			while(true){
				packetReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
				socket.receive(packetReceived);
				byte[] checkByte = packetReceived.getData();
				
				ByteBuffer buff = ByteBuffer.wrap(checkByte);
				
				int keyword_length = buff.getInt();
		      	byte[] keywd = new byte[keyword_length];
		        buff.get(keywd, 0, keyword_length);
		        
		        int dataByte_length = buff.getInt();
		      	byte[] dataByte = new byte[dataByte_length];
		        buff.get(dataByte, 0, dataByte_length);
		        
		        String keyword = new String(keywd);
		        keyword = keyword.trim();

		        if(keyword.equals(login)){
		        	SchatServer.loginManagement(packetReceived);
		        	continue;
		        	}
		        else if(keyword.equals(list)){
					SchatServer.listManagement(clist, packetReceived);
					continue;
					}
		        else if(keyword.equals(connect)){
		        	SchatServer.connectManagement(packetReceived);
		        	continue;
				}
		        else if(keyword.equals(logout)){
		        	SchatServer.logoutManagement(packetReceived);
		        	break;
		        	}
		        else{
		        	System.out.println("Invalid Data");
		        }
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}*/
	
	//METHOD TO MANAGE LOGOUT PROCESS
	public void logoutManagement(DatagramPacket logoutReq)throws Exception{
		System.out.println("LOGOUT REQUEST RECEIVED");
		logout_Res(logoutReq);
		
	}
	
	//METHOD TO DEAL WITH LOGOUT RESPONSE
	public void logout_Res(DatagramPacket logout_Req)throws Exception{
		
		SocketAddress SAddress = logout_Req.getSocketAddress();
		int port = logout_Req.getPort();
		byte[] logoutReq = logout_Req.getData();
		SecretKey Ksymm = null;
		
		 for(int i=0;i<clist.Info_clients.size();i++){
				if(clist.Info_clients.get(i).port_num == port){
					clist.Info_clients.get(i).IPAdrr = null;
					clist.Info_clients.get(i).port_num = 0;
					Ksymm = clist.Info_clients.get(i).Ksym;
				}
			}
		 
		ByteBuffer buff_1 = ByteBuffer.wrap(logoutReq);
		
		int keyword_length = buff_1.getInt();
      	byte[] keyword = new byte[keyword_length];
        buff_1.get(keyword, 0, keyword_length);
        
      
        byte[] N4 = logout.getBytes();
        
        int encrypted_length = buff_1.getInt();
      	byte[] encrypted = new byte[encrypted_length];
        buff_1.get(encrypted, 0, encrypted_length);
        
        byte[] decrypted = symmetricDecryption(encrypted, Ksymm);
        
        ByteBuffer buff_2 = ByteBuffer.wrap(decrypted);
		
		int N4rec_length = buff_2.getInt();
      	byte[] N4rec = new byte[N4rec_length];
        buff_2.get(N4rec, 0, N4rec_length);
        
        int uname_length = buff_2.getInt();
      	byte[] uname = new byte[uname_length];
        buff_2.get(uname, 0, uname_length);
        String user = new String();
        user = user.trim();
        
    
        
        byte[] ack_size = new byte[4 + N4.length];
        
        ByteBuffer buff_3 = ByteBuffer.wrap(ack_size);
        
        buff_3.putInt(N4.length);
        buff_3.put(N4);
        
        byte[] logout_ack_1 = buff_3.array();
        
       
        
        sendPacket(logout_ack_1, SAddress);
        System.out.println("User" + user + "LOGGED OUT SUCCESSFULLY");
        
	}
	
	//METHOD TO MANAGE LIST REQUEST
	public void listManagement(ClientList list, DatagramPacket list_req)throws Exception{
		
		System.out.println("LIST REQUEST RECEIVED");
		list_Res(list_req, list);
		
	}
	
	//METHOD TO DEAL WITH LIST RESPONSE
	public void list_Res(DatagramPacket list_Req, ClientList list)throws Exception{
		SecretKey Ksec = null;
		int portNumber = list_Req.getPort();
		
		byte[] listReq = list_Req.getData();
		ByteBuffer byteArray_req_1 = ByteBuffer.wrap(listReq);
		
		int keyword_length = byteArray_req_1.getInt();
      	byte[] keyword = new byte[keyword_length];
        byteArray_req_1.get(keyword, 0, keyword_length);
        
     
        
        int encrypted_length = byteArray_req_1.getInt();
      	byte[] encrypted = new byte[encrypted_length];
        byteArray_req_1.get(encrypted, 0, encrypted_length);
        
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).port_num == portNumber){
				 Ksec = clist.Info_clients.get(i).Ksym;
			}
		}
    	
        
        byte[] N5 = symmetricDecryption(encrypted, Ksec);
        byte[] onlineUsers = getList(list);
        
      
        
        byte[]  byteArray_res_length = new byte[4*2 + N5.length + onlineUsers.length];
		ByteBuffer byteArray_res = ByteBuffer.wrap(byteArray_res_length);
		
		byteArray_res.putInt(N5.length);
		byteArray_res.put(N5);
		byteArray_res.putInt(onlineUsers.length);
		byteArray_res.put(onlineUsers);
		
		byte[] list_Resp = byteArray_res.array();
		
		byte[] list_Response = symmetricEncryption(list_Resp, Ksec);
		sendPacket(list_Response, list_Req.getSocketAddress());
		System.out.println("LIST RESPONSE SENT");
	}
	
	
	//METHOD TO MANAGE CONNECTION PROCESS
	public void connectManagement(DatagramPacket connect_req)throws Exception{
		
		
		byte[] connectReq = connect_req.getData();
		System.out.println("CONNECT REQUEST RECEIVED");
		
		int port_number = connect_req.getPort();
		SocketAddress sAddress = connect_req.getSocketAddress();
		
		
		byte[] connect_res = connectResponse(connectReq, port_number);
		sendPacket(connect_res, sAddress);
		System.out.println("CONNECT RESPONSE SENT");
		
	}
	
	//METHOD TO DEAL WITH CONNECTION RESPONSE
	public byte[] connectResponse(byte[] connectReq, int port_number)throws Exception{
		byte[] connect_res = null;
		
		SecretKey Ksec = null;
		InetAddress IPAddress = null;
		int portNumber = 0;
		
		ByteBuffer byteArray_req_1 = ByteBuffer.wrap(connectReq);
		
		int keyword_length = byteArray_req_1.getInt();
      	byte[] keyword = new byte[keyword_length];
        byteArray_req_1.get(keyword, 0, keyword_length);
        
        int encrypted_length = byteArray_req_1.getInt();
      	byte[] encrypted = new byte[encrypted_length];
        byteArray_req_1.get(encrypted, 0, encrypted_length);
        
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).port_num == port_number){
				Ksec = clist.Info_clients.get(i).Ksym;
			}
		}
        
        byte[] connectReq_decrypted = symmetricDecryption(encrypted, Ksec);
        System.out.println(connectReq_decrypted);
        ByteBuffer byteArray_req_2 = ByteBuffer.wrap(connectReq_decrypted);
    
        int N1_length = byteArray_req_2.getInt();
      	byte[] N1 = new byte[N1_length];
        byteArray_req_2.get(N1, 0, N1_length);
        
        int uname_length = byteArray_req_2.getInt();
      	byte[] uname = new byte[uname_length];
        byteArray_req_2.get(uname, 0, uname_length);
        String otherUsername = new String(uname);
        otherUsername = otherUsername.trim();
        
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(otherUsername)){
				 IPAddress = clist.Info_clients.get(i).IPAdrr;
				 portNumber = clist.Info_clients.get(i).port_num;
			}
		}
        
        String keyFileName = otherUsername + "_Public.der";
        byte[] keyToSend = readFromFile(keyFileName);
        
        byte[]  byteArray_res_length = new byte[4*4 + N1.length + keyToSend.length + IPAddress.getAddress().length];
		ByteBuffer byteArray_res = ByteBuffer.wrap(byteArray_res_length);
        
		byteArray_res.putInt(N1.length);
		byteArray_res.put(N1);
		byteArray_res.putInt(keyToSend.length);
		byteArray_res.put(keyToSend);
		byteArray_res.putInt(IPAddress.getAddress().length);
		byteArray_res.put(IPAddress.getAddress());
		byteArray_res.putInt(portNumber);
		
		byte[] toEncrypt = byteArray_res.array();
		connect_res = symmetricEncryption(toEncrypt, Ksec);
        return connect_res;
	}
	
	
	//METHOD TO MANAGE LOGIN PROCESS
	public void loginManagement(DatagramPacket loginReq)throws Exception{
		
		System.out.println("LOGIN REQ RECEIVED");
		
		byte[] resp = loginResponse(loginReq);
		System.out.println("LOGIN RESPONSE SENT");
		String toCompare = new String(resp);
		if(toCompare.equals("Incorrect Username")){
			//keepRunning();
			
		}
		else{
			String username = new String (resp);
		
		
		
		DatagramPacket loginVer = receivePacket();
		System.out.println("LOGIN VERIFY RECEIVED");
		
	
		boolean loginAck = loginAck(loginVer, username);
	
		System.out.println("LOGIN ACK SENT");
		
		if(!loginAck){
			for(int i=0;i<clist.Info_clients.size();i++){
    			if(clist.Info_clients.get(i).name.equals(username)){
    				 clist.Info_clients.get(i).Ksym = null;
    				 clist.Info_clients.get(i).IPAdrr = null;
    				 clist.Info_clients.get(i).port_num = 0;
    			}
    		}
		}
		
		}
		
	}
	
	
	//METHOD TO DEAL WITH LOGIN ACKNOWLEDGE
	public boolean loginAck(DatagramPacket loginVer, String username)throws Exception{
		byte[] ack = null;
		byte[] storedHash = null;
		byte[] encryptedLoginVer = loginVer.getData();
		boolean match = false;
		SecretKey Ksymm = null;
		byte[] R = null;
    	byte[] toPut = "Incorrect Password".getBytes();
		
    	byte[] keyBytes = readFromFile("server_Private.der");
        
	
        byte[] decryptedLoginVer = asymmetricDecryption(encryptedLoginVer, keyBytes);
		ByteBuffer byteArray_ver = ByteBuffer.wrap(decryptedLoginVer);
		
		int N2_length = byteArray_ver.getInt();
		byte[] N2 = new byte[N2_length];
        byteArray_ver.get(N2, 0, N2_length);
		
        int N3_length = byteArray_ver.getInt();
		byte[] N3 = new byte[N3_length];
        byteArray_ver.get(N3, 0, N3_length);
        
        int hash_length = byteArray_ver.getInt();
		byte[] hash = new byte[hash_length];
        byteArray_ver.get(hash, 0, hash_length);
        
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(username)){
				 storedHash = clist.Info_clients.get(i).hash;
				 R = clist.Info_clients.get(i).random;
			}
		}
        
        String Rstrng = new String(R);
        
      
        
        
        
        int clientDHPublic_length = byteArray_ver.getInt();
    	byte[] clientDHPublic = new byte[clientDHPublic_length];
    	byteArray_ver.get(clientDHPublic, 0, clientDHPublic_length);
    
    	SecretKey Ks_c = DHSharedKeyGenerator(clientDHPublic, serverDHPair.getPrivate());
        
    	for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(username)){
				 clist.Info_clients.get(i).Ksym = Ks_c;
			}
		}
    	
        if(matches(Rstrng, hash, storedHash)){
        	match = true;
        	toPut = N3;
        	}

        
        byte[]  byteArray_ack_length = new byte[4 + toPut.length];
    	ByteBuffer byteArray_ack = ByteBuffer.wrap(byteArray_ack_length);
	
    	byteArray_ack.putInt(toPut.length);
    	byteArray_ack.put(toPut);
    
    	ack = byteArray_ack.array();
    	
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(username)){
				 Ksymm = clist.Info_clients.get(i).Ksym;
			}
		}
        
        byte[] finalAck = symmetricEncryption(ack, Ksymm);
        sendPacket(finalAck, loginVer.getSocketAddress());
        if(new String(toPut).equals("-1")&& loginAttempts < 3){
        	loginAttempts++;
        }
        if(loginAttempts == 2){

            for(int i=0;i<clist.Info_clients.size();i++){
    			if(clist.Info_clients.get(i).name.equals(username)){
    				 clist.Info_clients.get(i).Ksym = null;
    				 clist.Info_clients.get(i).IPAdrr = null;
    				 clist.Info_clients.get(i).port_num = 0;
    			}
    		}
        }
        return match;
	}
	
	//METHOD TO DEAL WITH LOGIN RESPONSE
	public byte[] loginResponse(DatagramPacket encryptedpacket)throws Exception{
		byte[] sa = new byte[1];
		int flag = 0;
		byte[] encrypted = encryptedpacket.getData(); 
		ByteBuffer byteArray_req = ByteBuffer.wrap(encrypted);
		
		int keyword_length = byteArray_req.getInt();
		byte[] keyword = new byte[keyword_length];
        byteArray_req.get(keyword, 0, keyword_length);
        
        int encryptedData_length = byteArray_req.getInt();
		byte[] encryptedData = new byte[encryptedData_length];
        byteArray_req.get(encryptedData, 0, encryptedData_length);
        
        
        
        
        byte[] keyBytes = readFromFile("server_Private.der");
        byte[] decryptedData = asymmetricDecryption(encryptedData, keyBytes);
        
       
        
        ByteBuffer byteArray2 = ByteBuffer.wrap(decryptedData);
        
        int N1_length = byteArray2.getInt();
      	byte[] N1 = new byte[N1_length];
        byteArray2.get(N1, 0, N1_length);
        
        int uname_length = byteArray2.getInt();
		byte[] uname = new byte[uname_length];
        byteArray2.get(uname, 0, uname_length);
        
        int clientPublic_length = byteArray2.getInt();
		byte[] clientPublic = new byte[clientPublic_length];
        byteArray2.get(clientPublic, 0, clientPublic_length);
        
        InetAddress clientAddr = encryptedpacket.getAddress();
		int clientport = encryptedpacket.getPort();
		
		String username = new String(uname);
        username = username.trim();
        
		for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(username)){
				clist.Info_clients.get(i).IPAdrr=clientAddr;
				clist.Info_clients.get(i).port_num=clientport;
				flag = 1;
			}
		}
		String fileName = username + "_Public.der";
        writeToFile(fileName, clientPublic);
        
        if(flag==0){
        	N1 = "Incorrect Username".getBytes();
        }
      
        int L2 = (int)Math.random() *1024;
        serverDHPair = DHPublicKeyGenerator(P, G, L2);
        byte[] DHPublicKey = serverDHPair.getPublic().getEncoded();
        
        byte[] N2 = GenerateNonce();
        
        byte[] R = randomNumber(128);
        
        for(int i=0;i<clist.Info_clients.size();i++){
			if(clist.Info_clients.get(i).name.equals(username)){
				sa = clist.Info_clients.get(i).salt;
				clist.Info_clients.get(i).random = R;
			}
		}
        
        byte[]  byteArray_res_length = new byte[4*5 + N1.length + N2.length + sa.length  + DHPublicKey.length + R.length];
		ByteBuffer byteArray_res = ByteBuffer.wrap(byteArray_res_length);
		
		byteArray_res.putInt(N1.length);
		byteArray_res.put(N1);
		byteArray_res.putInt(N2.length);
		byteArray_res.put(N2);
		byteArray_res.putInt(sa.length);
		byteArray_res.put(sa);
		byteArray_res.putInt(DHPublicKey.length);
		byteArray_res.put(DHPublicKey);
		byteArray_res.putInt(R.length);
		byteArray_res.put(R);
		
		
		
		byte[] login_res = asymmetricEncryption(byteArray_res.array(), clientPublic);
		
		sendPacket(login_res, encryptedpacket.getSocketAddress());
		
		if(flag == 0)
			return N1;
		else{
			return username.getBytes();
		}
		 
	}
	
	//METHOD TO GENERATE RANDOM NUMBER
	public static byte[] randomNumber(int numBits){
		long tstamp = (new Date()).getTime();
		ByteBuffer buffr = ByteBuffer.allocate(8);
		buffr.putLong(tstamp);
		byte[] timestamp =  buffr.array();
		
		SecureRandom gen = new SecureRandom(timestamp);
		int rand_num = Math.abs(gen.nextInt());
		int last =  (int) (rand_num % Math.pow(2, numBits));
		ByteBuffer byteArray = ByteBuffer.allocate(4);
		byteArray.putInt(last);
		return byteArray.array();
	}

	//METHOD TO GET LIST FROM DATABASE
	public byte[] getList(ClientList list)throws Exception{
		
		int flag = 0;
		int size = 0;
		int NumberOfOnlineClients = 0;
		ArrayList<byte[]> online_clients = new ArrayList<byte[]>();
		
		for(int i=0; i<list.Info_clients.size(); i++){
			if(list.Info_clients.get(i).port_num !=0)
				{System.out.println(list.Info_clients.get(i).name);
				online_clients.add(list.Info_clients.get(i).name.getBytes());
				size = size + list.Info_clients.get(i).name.getBytes().length;
				NumberOfOnlineClients++;
				flag=1;
			}
		}
		
		if(flag==0){
			String initial = new String("Zero Online");
	      	online_clients.add(initial.getBytes());
	      	NumberOfOnlineClients = 1;
	      	size = initial.getBytes().length;
		}

		byte[] clientBytes = new byte[4 + 4*online_clients.size() + size];
		ByteBuffer buff = ByteBuffer.wrap(clientBytes);
		buff.putInt(NumberOfOnlineClients);
		
		for(int j=0; j<online_clients.size(); j++){
			byte[] client = online_clients.get(j);
			buff.putInt(client.length);
			buff.put(client);
		}
		
		byte[] onlineClients = buff.array();
		
		return onlineClients;

	}
	
	//METHOD TO SEND PACKET
	public void sendPacket(byte[] dataToSend, SocketAddress destinationAddress)throws Exception{
		
		DatagramPacket sendPacket = new DatagramPacket(dataToSend, dataToSend.length, destinationAddress);
		socket.send(sendPacket);
	}
	
	
	//METHOD TO RECEIVE PACKET
	public DatagramPacket receivePacket()throws Exception{
		packetReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
		socket.receive(packetReceived);
		
		return packetReceived;
	}
	

	//THREAD TO KEEP SERVER UP AND RUNNING
	static class ServerReceive implements Runnable{
		
		public void run(){
			
			try{
				while(true){
					packetReceived = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
					socket.receive(packetReceived);
					byte[] checkByte = packetReceived.getData();
					
					ByteBuffer buff = ByteBuffer.wrap(checkByte);
					
					int keyword_length = buff.getInt();
			      	byte[] keywd = new byte[keyword_length];
			        buff.get(keywd, 0, keyword_length);
			        
			        int dataByte_length = buff.getInt();
			      	byte[] dataByte = new byte[dataByte_length];
			        buff.get(dataByte, 0, dataByte_length);
			        
			        String keyword = new String(keywd);
			        keyword = keyword.trim();

			        if(keyword.equals(login)){
			        	SchatServer.loginManagement(packetReceived);
			        	continue;
			        	}
			        else if(keyword.equals(list)){
						SchatServer.listManagement(clist, packetReceived);
						continue;
						}
			        else if(keyword.equals(connect)){
			        	SchatServer.connectManagement(packetReceived);
			        	continue;
					}
			        else if(keyword.equals(logout)){
			        	SchatServer.logoutManagement(packetReceived);
			        	continue;
			        	}
			        else{
			        	System.out.println("Invalid Data");
			        }
				}
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
	}

}
