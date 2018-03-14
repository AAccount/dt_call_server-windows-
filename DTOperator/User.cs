using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DTOperator
{
	class User
	{
		public String Name { get; }
		public Socket CommandSocket { get; set; }
		public RSACryptoServiceProvider PublicKey { get; set; }
		public String PublicKeyDump { get; set; }
		public String Challenge { get; set; }
		public String Sessionkey { get; set; }

		public IPEndPoint UdpInfo { get; set; }
		public Const.ustate UserState { get; set; } //can be used as hash table key, no need for summary
		public String CallWith { get; set; }

		public User(String cuname, RSACryptoServiceProvider cp, String cpd)
		{
			Name = cuname;
			PublicKey = cp;
			PublicKeyDump = cpd;

			//c++ unix version passes strings on the stack so... null strings don't exist.
			//keep the same logic in both versions for easier mental sorting
			Challenge = "";
			Sessionkey = "";
			CallWith = "";
		}
	}
}
