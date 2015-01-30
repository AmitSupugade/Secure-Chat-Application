import java.net.InetAddress;
import java.util.ArrayList;

import javax.crypto.SecretKey;


class InfoClient
{
	
	//Class Variables
	public String name;
	public String password;
	public byte[] hash;
	public InetAddress IPAdrr=null;
	public int port_num=0;
	public byte[] salt;
	public SecretKey Ksym = null;
	public byte[] random = null;
	
	//
	public InfoClient(InetAddress IPAdrr, int port_num)
	{
		this.IPAdrr = IPAdrr;
		this.port_num = port_num ; 
	}
	

	public InfoClient() {
		
	}
}


class ClientList
{
	// making a list of Client objects
	ArrayList<InfoClient> Info_clients; 
	public ClientList()
	{
		Info_clients = new ArrayList<InfoClient>();
		InfoClient temp = new InfoClient();
			Info_clients.add(temp);
			temp.name = "Ishan";
			
			
		temp = new InfoClient();
			Info_clients.add(temp);
			temp.name = "Amit";
			
                        
		temp = new InfoClient();
			Info_clients.add(temp);
			temp.name = "Guest";
			
			
	} 
}
