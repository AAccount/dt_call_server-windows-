# dt_call_server(windows)

Windows C# implementation of (https://github.com/AAccount/dt_call_server).

See the original unix version for information. It is designed exactly the same even using the same variable and function names where applicable. Instead of OpenSSL, it relies on Windows's native cryptography functions.

More of an academic exercise than actual use, it is tested but not as heavily as the unix version which runs on my own server. It is compatible with AClient 1.5 up to commit fdf2a22151b552b5734f21ad030d459f3b7f5d9a. AClient 1.5 past this commit has never been tested. AClient 1.6 and above will use libsodium for UDP encryption and public key login authentication which the Windows version doesn't implement.

![Main Output](https://github.com/AAccount/dt_call_server-windows-/blob/master/main%20output.png "Call Server Windows running in Windows 10 QEMU/KVM")
![MSSQL Logging](https://github.com/AAccount/dt_call_server-windows-/blob/master/mssql%20logging.png "MSSQL database logging results in Visual Studio 2017 on Windows 10 in QEMU/KVM")
