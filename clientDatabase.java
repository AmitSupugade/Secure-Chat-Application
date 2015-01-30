import java.net.InetAddress;
import java.util.ArrayList;

import javax.crypto.SecretKey;




public class clientDatabase
{
	public String name;
	public InetAddress IPAdrr=null;
	public int port_num=0;
	public SecretKey sKey = null;
	
}

class ConnectedClientList
{
	// making a list of InfoClient objects
	//ArrayList<clientDatabase> Info_clients =new ArrayList<clientDatabase>(); 
	
}
/*
class ClientList
{
	// making a list of InfoClient objects
	ArrayList<clientDatabase> Info_clients; 
public ClientList()
	{
		Info_clients = new ArrayList<clientDatabase>();
		clientDatabase temp = new clientDatabase();
			Info_clients.add(temp);
			temp.name = "Ishan";
			temp.password = "Kumar";
			
		
			
	} 
}
*/