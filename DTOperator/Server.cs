using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace DTOperator
{
	class Server
    {
		private static UserUtils userUtils = UserUtils.getInstance();
		private static Dictionary<Socket, SslStream> clientssl = new Dictionary<Socket, SslStream>();

        static void Main(string[] args)
        {
			String start = "Staring call operator (windows c#) V" + Const.VERSION;
			userUtils.InsertLog(new Log(Log.TAG_INIT, start, Log.SELF, Log.SYSTEM, Log.SELFIP));

			int cmdPort = Const.DEFAULTCMD;
			bool gotCmd = false;
			int mediaPort = Const.DEFAULTMEDIA;
			bool gotMedia = false;
			String mergedKeyFile = "";

			//c# doesn't have the openssl uglyness + c socket uglyness so no need to hide the conf parser somewhere else
			//establish ports and certificate file
			StreamReader confFile = new StreamReader(Const.CONFFILE);
			String line;
			while((line = confFile.ReadLine()) != null)
			{
				if(line.Length == 0 || line[0] == '#')
				{
					continue;
				}

				String[] contents = line.Split('=');
				if(contents.Length != 2)
				{
					continue;
				}
				String var = Utils.Trim(contents[0]);
				String value = Utils.Trim(contents[1]);

				if(var.Equals("command"))
				{
					cmdPort = Int16.Parse(value);
					gotCmd = true;
				}
				else if (var.Equals("media"))
				{
					mediaPort = Int16.Parse(value);
					gotMedia = true;
				}
				else if (var.Equals("merged")) //windows requires the public and private key glued together
				{
					mergedKeyFile = value;
				}
			}
			confFile.Close();

			//no certificate, no encrypted connections, end of story
			if(mergedKeyFile.Equals(""))
			{
				String error = "no merged public and private key supplied";
				userUtils.InsertLog(new Log(Log.TAG_INIT, error, Log.SELF, Log.ERROR, Log.SELFIP));
				return;
			}
			
			if(!gotCmd)
			{
				String warn = "using the default command port";
				userUtils.InsertLog(new Log(Log.TAG_INIT, warn, Log.SELF, Log.SYSTEM, Log.SELFIP));
			}
			if(!gotMedia)
			{
				String warn = "using the default media port";
				userUtils.InsertLog(new Log(Log.TAG_INIT, warn, Log.SELF, Log.SYSTEM, Log.SELFIP));
			}
			
			X509Certificate2 mergedKey = new X509Certificate2(mergedKeyFile);

			//setup the command fd/socket
			Socket commandSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			commandSocket.Bind(new IPEndPoint(IPAddress.Any, cmdPort));
			commandSocket.Listen(Const.MAXLISTENWAIT);

			//setup for udp thread
			Thread udpThread = new Thread(() => UdpThread(mediaPort, mergedKey));
			try
			{
				udpThread.Name = "VoUDP_win";
				udpThread.Start();
			}
			catch(Exception e)
			{
				String ex = e.Message + "\n" + e.StackTrace;
				userUtils.InsertLog(new Log(Log.TAG_INIT, ex, Log.SELF, Log.ERROR, Log.SELFIP));
				return; //no udp thread, can't do anything useful
			}

			while(true)
			{
				ArrayList readSockets = new ArrayList();
				readSockets.Add(commandSocket);

				foreach(KeyValuePair<Socket, SslStream> client in clientssl)
				{
					readSockets.Add(client.Key);
				}

				Socket.Select(readSockets, null, null, -1);
				for(int i=0; i<readSockets.Count; i++)
				{
					Socket socket = (Socket)readSockets[i];
					if (socket == commandSocket)
					{
						String incomingip = "(lost)";
						try //equivalent to C's accept not returning 0 and SSL_ERROR_something
						{
							Socket incoming = commandSocket.Accept();
							incomingip = incoming.RemoteEndPoint.ToString();
							incoming.ReceiveTimeout = Const.UNAUTHTIMEOUT;
							incoming.NoDelay = true;
							SslStream incomingSsl = new SslStream(new NetworkStream(incoming));
							incomingSsl.AuthenticateAsServer(mergedKey, false, System.Security.Authentication.SslProtocols.Tls12, false);
							clientssl.Add(incoming, incomingSsl);
							
						}
						catch(Exception e)
						{
							String ex = e.Message + "\n" + e.StackTrace;
							userUtils.InsertLog(new Log(Log.TAG_INCOMINGCMD, ex, Log.SELF, Log.ERROR, incomingip));
						}
						continue; //incoming socket, no need to do anything on it yet
					}

					//read the socket
					SslStream socketSsl = clientssl[socket];
					byte[] inputBuffer = new byte[Const.COMMANDSIZE+1];
					int amountRead = 0;
					try
					{
						amountRead = socketSsl.Read(inputBuffer, 0, Const.COMMANDSIZE);
					}
					catch(Exception e)
					{
						String ex = e.Message + "\n" + e.StackTrace;
						userUtils.InsertLog(new Log(Log.TAG_SSL, ex, Log.SELF, Log.ERROR, incomingip));
					}

					//remove dead sockets
					if(amountRead == 0)
					{
						Console.WriteLine("Removing dead socket: " + socket.ToString());
						RemoveClient(socket); //not iterating through clientssl like c++ so safe to immediately remove
						continue;
					}

					String bufferString = Encoding.ASCII.GetString(inputBuffer);
					bufferString = bufferString.Substring(0, amountRead);
				
					//check for jbyte
					if(bufferString.Equals(Const.JBYTE))
					{
						continue;
					}

					String[] commandContents = bufferString.Split('|');
					String ip = socket.RemoteEndPoint.ToString();
					long unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();

					try
					{
						//timestamp check
						long ts = Convert.ToInt64(commandContents.ElementAt(0));
						long diff = Math.Max(unixNow, ts) - Math.Min(unixNow, ts);
						if(diff > 60*Const.MARGIN_OF_ERROR)
						{
							String error = "command received outside the margin of error, seconds: " + diff;
							String name = userUtils.UserFromCommandSocket(socket);
							userUtils.InsertLog(new Log(Log.TAG_BADCMD, error, name, Log.ERROR, ip));
							Write2Client(unixNow + "|invalid", socket);
						}

						String command = commandContents.ElementAt(1);
						if(command.Equals("login1"))
						{//unixts|login1|user
							String name = commandContents.ElementAt(2);
							userUtils.InsertLog(new Log(Log.TAG_LOGIN, bufferString, name, Log.INBOUND, ip));
							RSACryptoServiceProvider publicKey = userUtils.GetPublicKey(name);
							if(publicKey == null)
							{//not a real user
								String invalid = unixNow + "|invalid";
								userUtils.InsertLog(new Log(Log.TAG_LOGIN, invalid, name, Log.ERROR, ip));
								Write2Client(invalid, socket);
								RemoveClient(socket);
								continue;
							}

							//generate challenge
							String challenge = Utils.RandomString(Const.CHALLENGE_LENGTH);
							userUtils.SetChallenge(name, challenge);
							byte[] challengeEnc = publicKey.Encrypt(new ASCIIEncoding().GetBytes(challenge), RSAEncryptionPadding.OaepSHA1);
							String encString = Stringify(challengeEnc);

							//send challenge
							String resp = unixNow + "|login1resp|" + encString;
							Write2Client(resp, socket);
							userUtils.InsertLog(new Log(Log.TAG_LOGIN, resp, name, Log.OUTBOUND, ip));
							continue;
						}
						else if(command.Equals("login2"))
						{//unixts|login2|user|challengedec
							String name = commandContents.ElementAt(2);
							String triedChallenge = commandContents.ElementAt(3);
							userUtils.InsertLog(new Log(Log.TAG_LOGIN, bufferString, name, Log.INBOUND, ip));

							//check challenge answer and don't allow loophole
							String answer = userUtils.GetChallenge(name);
							if(answer.Equals("") || triedChallenge != answer)
							{
								String invalid = unixNow + "|invalid";
								userUtils.InsertLog(new Log(Log.TAG_LOGIN, invalid, name, Log.OUTBOUND, ip));
								Write2Client(invalid, socket);
								RemoveClient(socket);

								userUtils.SetChallenge(name, "");
								continue;
							}

							//adjust timeout for authenticated sockets
							socket.ReceiveTimeout = Const.AUTHTIMEOUT;

							//now that it is certain the login is legitimately from the user, remove the old stuff
							Socket oldcmd = userUtils.GetCommandSocket(name);
							if(oldcmd != null)
							{
								RemoveClient(oldcmd);
							}
							userUtils.ClearSession(name);

							//set the internal db information
							String skey = Utils.RandomString(Const.SESSIONKEY_LENGTH);
							userUtils.SetSessionkey(name, skey);
							userUtils.SetCommandFd(skey, socket);
							userUtils.SetChallenge(name, "");

							//send ok + session key
							String resp = unixNow + "|login2resp|" + skey;
							Write2Client(resp, socket);
							resp = unixNow + "|login2resp|" + Const.SESSIONKEY_PLACEHOLDER;
							userUtils.InsertLog(new Log(Log.TAG_LOGIN, resp, name, Log.OUTBOUND, ip));
							continue;
						}

						//check the sessionid for all non login commands
						String sessionkey = commandContents.ElementAt(commandContents.Length - 1);
						String user = userUtils.UserFromCommandSocket(socket);
						bufferString.Replace(sessionkey, Const.SESSIONKEY_PLACEHOLDER);

						//no use continuing a valid session key verification
						if(!userUtils.VerifySessionkey(sessionkey, socket))
						{
							String error = "sessionkey verification failed, refusing (" + bufferString + ")";
							userUtils.InsertLog(new Log(Log.TAG_BADCMD, error, user, Log.ERROR, ip));

							String invalid = unixNow + "|invalid";
							Write2Client(invalid, socket);
							userUtils.InsertLog(new Log(Log.TAG_BADCMD, invalid, user, Log.OUTBOUND, ip));
							continue;
						}

						if (command.Equals("call"))
						{//unixts|call|zapper|toumakey

							String zapper = commandContents.ElementAt(2);
							String touma = user;
							userUtils.InsertLog(new Log(Log.TAG_CALL, bufferString, user, Log.INBOUND, ip));
							Socket zapperSocket = userUtils.GetCommandSocket(zapper);

							//find out if zapper is available to call
							bool offline = (zapperSocket == null);
							bool busy = (!userUtils.GetCallWith(zapper).Equals(""));
							bool selfDial = (touma.Equals(zapper));
							if (offline || busy || selfDial)
							{
								String na = unixNow + "|end|" + zapper;
								Write2Client(na, socket);
								userUtils.InsertLog(new Log(Log.TAG_CALL, na, user, Log.OUTBOUND, ip));
								continue;
							}

							//setup statuses and register call
							userUtils.SetUserState(touma, Const.ustate.INIT);
							userUtils.SetUserState(zapper, Const.ustate.INIT);
							userUtils.SetCallPair(zapper, touma);

							String notifyTouma = unixNow + "|available|" + zapper;
							Write2Client(notifyTouma, socket);
							userUtils.InsertLog(new Log(Log.TAG_CALL, notifyTouma, touma, Log.OUTBOUND, ip));

							String notifyZapper = unixNow + "|incoming|" + touma;
							Write2Client(notifyZapper, zapperSocket);
							userUtils.InsertLog(new Log(Log.TAG_CALL, notifyZapper, zapper, Log.OUTBOUND, zapperSocket.RemoteEndPoint.ToString()));
						}
						else if(command.Equals("passthrough"))
						{//unixts|passthrough|zapper|encrypted aes key|toumakey
							String zapper = commandContents.ElementAt(2);
							String touma = user;
							String aes = commandContents.ElementAt(3);
							bufferString.Replace(aes, Const.ENCAES_PLACEHOLDER);
							userUtils.InsertLog(new Log(Log.TAG_PASSTHROUGH, bufferString, touma, Log.INBOUND, ip));

							if(!IsRealCall(touma, zapper, Log.TAG_PASSTHROUGH))
							{
								continue;
							}

							Socket zapperSocket = userUtils.GetCommandSocket(zapper);
							if(zapperSocket != null)
							{
								String direct = unixNow + "|direct|" + aes + "|" + touma;
								Write2Client(direct, zapperSocket);
								direct.Replace(aes, Const.ENCAES_PLACEHOLDER);
								userUtils.InsertLog(new Log(Log.TAG_PASSTHROUGH, direct, zapper, Log.OUTBOUND, zapperSocket.RemoteEndPoint.ToString()));
							}
							else
							{
								String error = "??? person to passthrough to has a null socket??";
								userUtils.InsertLog(new Log(Log.TAG_PASSTHROUGH, error, zapper, Log.ERROR, "??missing??"));
							}
						}
						else if(command.Equals("ready"))
						{//unixts|ready|touma|zapperkey
							String zapper = user;
							String touma = commandContents.ElementAt(3);
							userUtils.InsertLog(new Log(Log.TAG_READY, bufferString, zapper, Log.INBOUND, ip));
							if(!IsRealCall(zapper, touma, Log.TAG_READY))
							{
								continue;
							}

							userUtils.SetUserState(zapper, Const.ustate.INCALL);
							if(userUtils.GetUserState(touma) == Const.ustate.INCALL)
							{
								Socket toumaSocket = userUtils.GetCommandSocket(touma);
								String toumaResp = unixNow + "|start|" + zapper;
								Write2Client(toumaResp, toumaSocket);
								userUtils.InsertLog(new Log(Log.TAG_READY, toumaResp, touma, Log.OUTBOUND, toumaSocket.RemoteEndPoint.ToString()));

								String zapperResp = unixNow + "|start|" + touma;
								Write2Client(zapperResp, socket);
								userUtils.InsertLog(new Log(Log.TAG_READY, zapperResp, zapper, Log.OUTBOUND, ip));
							}
						}
						else if(command.Equals("end"))
						{//unixts|end|zapper|toumakey
							String zapper = commandContents.ElementAt(2);
							String touma = user;
							userUtils.InsertLog(new Log(Log.TAG_END, bufferString, touma, Log.INBOUND, ip));
							if(!IsRealCall(touma, zapper, Log.TAG_END))
							{
								continue;
							}

							//reset state and deregister call
							userUtils.SetUserState(touma, Const.ustate.NONE);
							userUtils.SetUserState(zapper, Const.ustate.NONE);
							userUtils.RemoveCallPair(touma);

							//send hang up
							String end = unixNow + "|end|" + touma;
							Socket zapperSocket = userUtils.GetCommandSocket(zapper);
							Write2Client(end, zapperSocket);
							userUtils.InsertLog(new Log(Log.TAG_END, end, zapper, Log.OUTBOUND, zapperSocket.RemoteEndPoint.ToString()));
						}
					}
					catch (Exception e)
					{
						String stacktrace = e.Message +"\n"+ e.StackTrace;
						String user = userUtils.UserFromCommandSocket(socket);
						userUtils.InsertLog(new Log(Log.TAG_BADCMD, stacktrace, user, Log.INBOUND, ip));

						String invalid = unixNow + "|invalid";
						Write2Client(invalid, socket);
						userUtils.InsertLog(new Log(Log.TAG_BADCMD, invalid, user, Log.OUTBOUND, ip));
						continue;
					}
				}
			}
        }

		private static void UdpThread(int port, X509Certificate2 serverKeys)
		{
			//setup the udp socket and private key decryptor
			UdpClient udp = new UdpClient(port);
			udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, Const.IPTOS_DSCP_EF);
			RSACryptoServiceProvider privateKey = (RSACryptoServiceProvider)serverKeys.PrivateKey;

			while (true)
			{
				//receive udp
				IPEndPoint sender = new IPEndPoint(IPAddress.Any, 0);
				byte[] media;
				try
				{
					media = udp.Receive(ref sender);
				}
				catch (Exception e)
				{
					String error = e.Message + "\n" + e.StackTrace;
					userUtils.InsertLog(new Log(Log.TAG_UDPTHRAD, error, Log.SELF, Log.ERROR, sender.ToString()));
					continue;
				}

				//figure out who sent it
				String user = userUtils.UserFromUdpInfo(sender);
				Const.ustate state = userUtils.GetUserState(user);

				//new registration or registration re-attempt
				if( user.Equals("") || state == Const.ustate.INIT )
				{
					//check registration received is doable
					Console.WriteLine("sending ack for: " + sender.ToString() + " " + user);
					if(media.Length > serverKeys.PrivateKey.KeySize)
					{
						Console.WriteLine("udp packet invalid length for key size");
						continue;
					}

					//decrypt registration
					byte[] decMedia = privateKey.Decrypt(media, RSAEncryptionPadding.OaepSHA1);
					String decMediaString = new ASCIIEncoding().GetString(decMedia);
					String[] decMediaContents = decMediaString.Split('|');

					try
					{
						//check timestamp
						long ts = Convert.ToInt64(decMediaContents.ElementAt(0));
						long unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();
						long diff = Math.Max(ts, unixNow) - Math.Min(ts, unixNow);
						if(diff > Const.MARGIN_OF_ERROR*60)
						{
							String error = "media port registration timestamp too far off, diff:" + diff;
							userUtils.InsertLog(new Log(Log.TAG_UDPTHRAD, error, user, Log.ERROR, sender.ToString()));
							continue;
						}

						//if this is a new registration, figure out who it is
						if(user.Equals(""))
						{
							String sessionkey = decMediaContents.ElementAt(1);
							userUtils.SetUdpInfo(sessionkey, sender);
							user = userUtils.UserFromSessionkey(sessionkey);
						}

						//encrypt registration ack
						String ack = unixNow + "|" + userUtils.GetSessionkey(user) + "|ok";
						byte[] ackBytes = new ASCIIEncoding().GetBytes(ack);
						byte[] ackEnc = userUtils.GetPublicKey(user).Encrypt(ackBytes, RSAEncryptionPadding.OaepSHA1);

						//send encrypted ack
						udp.Send(ackEnc, ackEnc.Length, sender);
					}
					catch(Exception e)
					{
						String ex = e.Message + "\n" + e.StackTrace;
						userUtils.InsertLog(new Log(Log.TAG_UDPTHRAD, ex, user, Log.ERROR, sender.ToString()));
					}
				}
				else if(state == Const.ustate.INCALL)
				{
					//find the other person in the call
					String otherPerson = userUtils.GetCallWith(user);
					if(otherPerson.Equals(""))
					{
						continue;
					}

					//passthrough of media to the other person
					try
					{
						IPEndPoint otherPersonAddr = userUtils.GetUdpInfo(otherPerson);
						udp.Send(media, media.Length, otherPersonAddr);
					}
					catch(Exception e)
					{
						String ex = e.Message + "\n" + e.StackTrace;
						userUtils.InsertLog(new Log(Log.TAG_UDPTHRAD, ex, user, Log.ERROR, sender.ToString()));
					}
				}
			}
			Console.WriteLine("Exiting udp thread???");
		}

		private static String Stringify(byte[] input)
		{
			String result = "";
			for(int i=0; i<input.Length; i++)
			{
				String number = Convert.ToString(input[i]);
				if(input[i] < 10)
				{
					number = "00" + number;
				}
				else if(input[i] < 100)
				{
					number = "0" + number;
				}
				result = result + number;
			}
			return result;
		}

		private static void RemoveClient(Socket client)
		{
			String uname = userUtils.UserFromCommandSocket(client);
			SslStream ssl = clientssl[client];
			clientssl.Remove(client);
			ssl.Close();
			client.Close();
			userUtils.ClearSession(uname);
		}

		private static void Write2Client(String response, Socket socket)
		{
			String user = userUtils.UserFromCommandSocket(socket);
			String ip = socket.RemoteEndPoint.ToString();
			byte[] responseBytes = new ASCIIEncoding().GetBytes(response);

			SslStream socketSsl = clientssl[socket];
			try
			{
				socketSsl.Write(responseBytes);
			}
			catch (Exception e)
			{
				String exDump = e.Message + "\n" + e.StackTrace;
				userUtils.InsertLog(new Log(Log.TAG_SSL, exDump, user, Log.ERROR, ip));
			}
		}
		
		private static bool IsRealCall(String a, String b, String tag)
		{
			bool real = true;

			String awith = userUtils.GetCallWith(a);
			String bwith = userUtils.GetCallWith(b);
			if((awith.Equals("")) || (bwith.Equals("")))
			{
				real = false;
			}

			if(!(awith.Equals(bwith)) || !(bwith.Equals(awith)))
			{
				real = false;
			}

			if(!real)
			{
				Socket socket = userUtils.GetCommandSocket(a);
				String ip = "(n/a??)";
				if(socket != null) //unlikely since this person was just online to send this invalid command
				{
					ip = socket.RemoteEndPoint.ToString();

					long unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();
					String invalid = unixNow + "|invalid";
					Write2Client(invalid, socket);
					userUtils.InsertLog(new Log(tag, invalid, a, Log.OUTBOUND, ip));
				}
				String error = a + " sent a command for a non existant call with " + b;
				userUtils.InsertLog(new Log(tag, error, a, Log.ERROR, ip));

			}

			return real;
		}
    }
}
