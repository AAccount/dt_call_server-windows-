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

		private DateTime logStamp;
		private FileStream logger;

		public static UserUtils getInstance()
		{
			if(instance == null)
			{
				instance = new UserUtils();
			}
			return instance;
		}

		private UserUtils()
		{
			StreamReader usersfile = new StreamReader(Const.USERSFILE);
			String line;
			while((line = usersfile.ReadLine()) != null)
			{
				if(line.Length == 0 || line[0] == '#')
				{
					continue;
				}

				String[] contents = line.Split('>');
				if(contents.Length != 2)
				{
					Console.WriteLine("Users file line '" + line + "' is misconfigured");
					continue;
				}
				String uname = Utils.Trim(contents[0]);
				String path = Utils.Trim(contents[1]);

				RSACryptoServiceProvider publicKey = Key.PemKeyUtils.GetRSAProviderFromPemFile(path);
				if(publicKey == null)
				{
					Console.WriteLine("Problems creating public key obj for " + uname);
					continue;
				}

				String publicKeyDump = File.ReadAllText(contents[1]);
				if(publicKeyDump == null || publicKeyDump.Equals(""))
				{
					Console.WriteLine("Public key dump to string failed for: " + uname);
				}

				User user = new User(uname, publicKey, publicKeyDump);
				if(nameMap.ContainsKey(uname))
				{
					Console.WriteLine("Duplicate account entires for: " + uname);
					nameMap.Remove(uname);
				}
				nameMap[uname] = user;
			}
			usersfile.Close();

			logStamp = DateTime.Now;
			String nowString = logStamp.ToString("MM_dd_yyyy_HH_mm") + ".log"; //windows version uses file extensions
			logger = new FileStream(Const.LOGFOLDER + nowString, FileMode.OpenOrCreate);
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
			return commandSocketMap[socket].Name;
		}

		public String UserFromSessionkey(String sessionkey)
		{
			if(!sessionkeyMap.ContainsKey(sessionkey))
			{
				String error = "nobody has that session key";
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return "";
			}
			return sessionkeyMap[sessionkey].Name;
		}

		public Socket GetCommandSocket(String user)
		{
			if(!nameMap.ContainsKey(user))
			{
				String error = "tried to get a command socket for somebody that doesn't exist " + user;
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return null;
			}
			return nameMap[user].CommandSocket;
		}

		public String GetSessionkey(String user)
		{
			if (!nameMap.ContainsKey(user))
			{
				String error = "tried to get a session key for somebody that doesn't exist";
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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
				InsertLog(new Log(Log.TAG_USERUTILS, error, Log.SELF, Log.ERROR, Log.SELFIP));
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

		public void InsertLog(Log log)
		{
			DateTime now = DateTime.Now;
			if((now - logStamp).Days > 0)
			{
				logger.Close();
				logStamp = now;
				String nowString = now.ToString("MM_DD_YYYY_HH_MM") + ".log";
				logger = new FileStream(Const.LOGFOLDER + nowString, FileMode.OpenOrCreate);
			}

			byte[] logbytes = log.ToBytes();
			logger.Write(logbytes, 0, logbytes.Length);
			logger.Flush();
			Console.WriteLine(log);
		}
	}
}
