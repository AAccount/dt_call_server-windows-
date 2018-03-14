using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DTOperator
{
	class Log
	{
		private static readonly ASCIIEncoding ascii = new ASCIIEncoding();

		public static readonly String INBOUND = "inbound";
		public static readonly String OUTBOUND = "outbound";
		public static readonly String ERROR = "error";
		public static readonly String SYSTEM = "system";

		public static readonly String SELF = "dtoperator_win";
		public static readonly String SELFIP = "self_win";
		public static readonly String DONTKNOW = "???";

		public static readonly String TAG_INIT = "init";
		public static readonly String TAG_USERUTILS = "user utils";
		public static readonly String TAG_BADCMD = "bad command";
		public static readonly String TAG_SSL = "ssl operations";
		public static readonly String TAG_LOGIN = "login";
		public static readonly String TAG_INCOMINGCMD = "incoming command socket";
		public static readonly String TAG_UDPTHRAD = "udp thread";
		public static readonly String TAG_CALL = "call command";
		public static readonly String TAG_ACCEPT = "accept command";
		public static readonly String TAG_END = "end command";
		public static readonly String TAG_PASSTHROUGH = "passthrough command";
		public static readonly String TAG_READY = "ready command";
		public static readonly String TAG_SOCKET = "socket obj"; //tag doesn't exist in unix c/c++ version
		public static readonly String TAG_DBUTILS = "mssql dbutils";

		public String Tag { get; }
		public String Message { get; }
		public String User { get; }
		public String Type { get; }
		public String Ip { get; }
		public Log(String ctag, String cmessage, String cuser, String ctype, String cip)
		{
			Tag = ctag;
			Message = cmessage;
			Type = ctype;
			User = cuser;
			Ip = cip;
		}

		public override String ToString()
		{
			return DateTime.Now.ToString("MMMM dd yyyy HH:mm") + " tag=" + Tag + "; message=" + Message + "; user=" + User + "; type=" + Type
				+ "; ip=" + Ip + "\n";
		}

		public byte[] ToBytes()
		{
			String self = ToString();
			byte[] selfbytes = ascii.GetBytes(self);
			return selfbytes;
		}
	}
}
