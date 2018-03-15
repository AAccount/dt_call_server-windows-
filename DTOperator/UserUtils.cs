using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DTOperator
{
	class UserUtils
	{
		private static UserUtils instance = null;
		private Dictionary<String, User> nameMap = new Dictionary<String, User>();
		private Dictionary<Socket, User> commandSocketMap = new Dictionary<Socket, User>();
		private Dictionary<String, User> sessionkeyMap = new Dictionary<String, User>();
		private Dictionary<IPEndPoint, User> udpMap = new Dictionary<IPEndPoint, User>();
		private Logger fileLogger = Logger.GetInstance();

		public static UserUtils GetInstance()
		{
			if(instance == null)
			{
				instance = new UserUtils();
			}
			return instance;
		}

		private UserUtils()
		{
			if (!Server.DBAccounts)
			{
				StreamReader usersfile = new StreamReader(Const.USERSFILE);
				String line;
				while ((line = usersfile.ReadLine()) != null)
				{
					if (line.Length == 0 || line[0] == '#')
					{
						continue;
					}

					String[] contents = line.Split('>');
					if (contents.Length != 2)
					{
						Console.WriteLine("Users file line '" + line + "' is misconfigured");
						continue;
					}
					String uname = Utils.Trim(contents[0]);
					String path = Utils.Trim(contents[1]);
					
					RSACryptoServiceProvider publicKey = Key.PemKeyUtils.GetRSAProviderFromPemFile(path);
					if (publicKey == null)
					{
						Console.WriteLine("Problems creating public key obj for " + uname);
						continue;
					}

					String publicKeyDump = File.ReadAllText(contents[1]);
					if (publicKeyDump == null || publicKeyDump.Equals(""))
					{
						Console.WriteLine("Public key dump to string failed for: " + uname);
					}

					User user = new User(uname, publicKey, publicKeyDump);
					if (nameMap.ContainsKey(uname))
					{
						Console.WriteLine("Duplicate account entires for: " + uname);
						nameMap.Remove(uname);
					}
					nameMap[uname] = user;
				}
				usersfile.Close();
			}
		}

		//dynamically load the certificate (if changed) or disable the account
		//	according to the MSSql database
		//returns true: account changed (should remove sockets and start fresh), false: no change
		public bool DynamicLoad(String username)
		{
			if (!Server.DBAccounts)
			{
				Logger.GetInstance().InsertLog(new Log(Log.TAG_USERUTILS, "tried to dynamic load when not in accounts db mode", Log.SELF, Log.ERROR, Log.SELFIP));
				return false; //nothing loaded from the DB, nothing changed.
			}

			//check if the account is enabled
			DBUtils dbutils = DBUtils.GetInstnace();
			bool enabled = dbutils.IsEnabled(username);
			if(!enabled)
			{
				if(nameMap.ContainsKey(username))
				{
					//account exists but is now disabled
					//	kill the public key in the in-memory db to make the account
					//	look like it doesn't exist anymore
					nameMap[username].PublicKey = null;
					nameMap[username].PublicKeyDump = "";
					return true; //account has changed
				}
				else
				{
					return false; //nothing was there to begin with, nothing changed
				}
			}

			//if the account isn't in the in-memory db add it
			String dbPublicKey = dbutils.GetDump(username);
			dbPublicKey = dbPublicKey.Replace("\r", "");
			RSACryptoServiceProvider dbRSA = Key.PemKeyUtils.GetRSAProviderFromPemDump(dbPublicKey);
			if (!nameMap.ContainsKey(username))
			{
				User user = new User(username, dbRSA, dbPublicKey);
				nameMap[username] = user;
				return true;
			}

			//if the account exists in the in-memory db check if the public key changed
			String currentPublicKey = nameMap[username].PublicKeyDump;
			if(!dbPublicKey.Equals(currentPublicKey))
			{
				//public key changed
				User user = nameMap[username];
				user.PublicKey = dbRSA;
				user.PublicKeyDump = dbPublicKey;
				return true;
			}
			return false;
		}

		public RSACryptoServiceProvider GetPublicKey(String username)
		{
			if(nameMap.ContainsKey(username))
			{
				return nameMap[username].PublicKey;
			}
			return null;
		}

		public String GetChallenge(String username)
		{
			if(nameMap.ContainsKey(username))
			{
				return nameMap[username].Challenge;
			}
			return "";
		}

		public void SetChallenge(String username, String challenge)
		{
			if(nameMap.ContainsKey(username))
			{
				nameMap[username].Challenge = challenge;
			}
			else
			{
				String error = "trying to set a challenge for somebody that doesn't exist: " + username;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public void SetSessionkey(String username, String sessionkey)
		{
			if(nameMap.ContainsKey(username))
			{
				nameMap[username].Sessionkey = sessionkey;
				sessionkeyMap[sessionkey] = nameMap[username];
			}
			else
			{
				String error = "trying to set a session key for somebody that doesn't exist: " + username;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public void SetCommandSocket(String sessionkey, Socket socket)
		{
			if(sessionkeyMap.ContainsKey(sessionkey))
			{
				User user = sessionkeyMap[sessionkey];
				Socket oldsocket = user.CommandSocket;
				if (oldsocket != null)
				{
					commandSocketMap.Remove(oldsocket);
				}
				user.CommandSocket = socket;
				commandSocketMap[socket] = user;
			}
			else
			{
				String error = "trying to set a command fd for a session key that isn't real";
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}



		public void ClearSession(String username)
		{
			if(nameMap.ContainsKey(username))
			{
				User user = nameMap[username];

				sessionkeyMap.Remove(user.Sessionkey);
				user.Sessionkey = "";

				if (user.CommandSocket != null)
				{
					commandSocketMap.Remove(user.CommandSocket);
					user.CommandSocket = null;
				}

				RemoveCallPair(username);
				ClearUdpInfo(username);
			}
			else
			{
				String error = "trying to clear a session for somebody that doesn't exist " + username;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public bool VerifySessionkey(String sessionkey, Socket socket)
		{
			if(!sessionkeyMap.ContainsKey(sessionkey))
			{
				return false;
			}
			return sessionkeyMap[sessionkey].CommandSocket.Equals(socket);
		}

		public String UserFromCommandSocket(Socket socket)
		{
			if(!commandSocketMap.ContainsKey(socket))
			{
				String error = "no user owns the socket object";
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
			return commandSocketMap[socket].Name;
		}

		public String UserFromSessionkey(String sessionkey)
		{
			if(!sessionkeyMap.ContainsKey(sessionkey))
			{
				String error = "nobody has that session key";
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
			return sessionkeyMap[sessionkey].Name;
		}

		public Socket GetCommandSocket(String user)
		{
			if(!nameMap.ContainsKey(user))
			{
				String error = "tried to get a command socket for somebody that doesn't exist " + user;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return null;
			}
			return nameMap[user].CommandSocket;
		}

		public String GetSessionkey(String user)
		{
			if (!nameMap.ContainsKey(user))
			{
				String error = "tried to get a session key for somebody that doesn't exist";
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
			return nameMap[user].Sessionkey;
		}

		public String UserFromUdpInfo(IPEndPoint udp)
		{
			if(udpMap.ContainsKey(udp))
			{
				return udpMap[udp].Name;
			}
			return "";
		}

		public void SetUdpInfo(String sessionkey, IPEndPoint udp)
		{
			if(sessionkeyMap.ContainsKey(sessionkey))
			{
				User user = sessionkeyMap[sessionkey];
				user.UdpInfo = udp;
				udpMap[udp] = user;
			}
			else
			{
				String error = "tried to set udp info for a non existant session key";
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public IPEndPoint GetUdpInfo(String uname)
		{
			if (nameMap.ContainsKey(uname))
			{
				return nameMap[uname].UdpInfo;
			}
			else
			{
				String error = "tried to get udp info for somebody that doesn't exist: " + uname;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return null;
			}
		}

		public void ClearUdpInfo(String uname)
		{
			if (nameMap.ContainsKey(uname))
			{
				User user = nameMap[uname];
				if (user.UdpInfo != null)
				{
					udpMap.Remove(user.UdpInfo);
					user.UdpInfo = null;
				}
				user.UserState = Const.ustate.NONE;
			}
			else
			{
				String error = "tried to clear udp info for somebody that doesn't exist: " + uname;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public Const.ustate GetUserState(String uname)
		{
			if(nameMap.ContainsKey(uname))
			{
				return nameMap[uname].UserState;
			}
			else
			{
				String error = "tried to get the user state of somebody that doesn't exist: " + uname;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return Const.ustate.NONE;
			}
		}

		public void SetUserState(String uname, Const.ustate state)
		{
			if(nameMap.ContainsKey(uname))
			{
				nameMap[uname].UserState = state;
			}
			else
			{
				String error = "tried to set the user state for somebody that doesn't exist: " + uname;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
			}
		}

		public String GetPublicKeyDump(String uname)
		{
			if (nameMap.ContainsKey(uname))
			{
				return nameMap[uname].PublicKeyDump;
			}
			else
			{
				String error = "tried to get the public key of somebody that doesn't exist: " + uname;
				fileLogger.InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
		}

		public String GetCallWith(String uname)
		{
			if (nameMap.ContainsKey(uname))
			{
				return nameMap[uname].CallWith;
			}
			return "";
		}

		public void SetCallPair(String a, String b)
		{
			if(nameMap.ContainsKey(a) && nameMap.ContainsKey(b))
			{
				nameMap[a].CallWith = b;
				nameMap[b].CallWith = a;
			}
		}

		public void RemoveCallPair(String a)
		{
			if(nameMap.ContainsKey(a) && nameMap.ContainsKey(nameMap[a].CallWith))
			{
				String other = nameMap[a].CallWith;
				nameMap[a].CallWith = "";
				nameMap[other].CallWith = "";
			}
		}
	}
}
