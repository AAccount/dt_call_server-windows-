using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DTOperator
{
	class Log
	{
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

		private String tag, message, user, type, ip;
		public Log(String ctag, String cmessage, String cuser, String ctype, String cip)
		{
			tag = ctag;
			message = cmessage;
			type = ctype;
			user = cuser;
			ip = cip;
		}

		public override String ToString()
		{
			return "tag=" + tag + "; message=" + message + "; user=" + user + "; type=" + type
				+ "; ip=" + ip + "\n";
		}

		public byte[] ToBytes()
		{
			String self = ToString();
			byte[] selfbytes = new ASCIIEncoding().GetBytes(self);
			return selfbytes;
		}
	}
}
