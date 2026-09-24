# NoMercy.SMBLibrary

A NoMercy fork of [SMBLibrary](https://github.com/TalAloni/SMBLibrary) by Tal Aloni: a pure C# implementation of SMB 1.0/CIFS, SMB 2.0/2.1 and SMB 3.0, client and server. One managed `netstandard2.0` assembly, no native dependencies, so it runs on every .NET platform.

The fork adds one thing: the client can connect to an SMB server on **any port**, not only 445.

## Install

```
dotnet add package NoMercy.SMBLibrary
```

The package contains `NoMercy.SMBLibrary.dll` and its helper assembly `NoMercy.SMBLibrary.Utilities.dll`. Its only dependency is `System.Buffers`.

The assembly names start with `NoMercy.`, so this package can sit next to the upstream `SMBLibrary` package without a name collision. The namespaces are unchanged (`SMBLibrary`, `SMBLibrary.Client`), so upstream code and examples work as written.

## Connect on a custom port

Stock SMBLibrary connects on port 445 (direct TCP) or 139 (NetBIOS). The port-taking overload exists but is `protected internal`. This fork makes it public on `ISMBClient`, `SMB2Client` and `SMB1Client`:

```csharp
bool Connect(IPAddress serverAddress, SMBTransportType transport, int port);
```

Example: list the shares of a server that listens on port 4450.

```csharp
using System.Net;
using SMBLibrary;
using SMBLibrary.Client;

var client = new SMB2Client();
if (!client.Connect(IPAddress.Parse("192.168.1.20"), SMBTransportType.DirectTCPTransport, 4450))
    throw new InvalidOperationException("Could not reach the SMB server");

NTStatus status = client.Login(string.Empty, "user", "password");
if (status != NTStatus.STATUS_SUCCESS)
    throw new UnauthorizedAccessException(status.ToString());

List<string> shares = client.ListShares(out status);
foreach (string share in shares)
    Console.WriteLine(share);

client.Logoff();
client.Disconnect();
```

Everything else, including NTLM/NTLMv2 authentication, file access through `TreeConnect` and `ISMBFileStore`, and the SMB server, behaves exactly as upstream. See the upstream documentation for the full API.

## Versions

The version follows the upstream release it is based on, with a `-nomercy.N` suffix: `1.5.7-nomercy.1` is upstream 1.5.7 plus fork change 1.

Based on upstream commit `7742c28` (1.5.7 line).

## License

LGPL-3.0-or-later, the same as upstream. See [src/License.txt](src/License.txt). Copyright © Tal Aloni 2014-2026; fork changes by NoMercy Entertainment.

You can use this package in closed-source software, because it links as a separate assembly. If you change the library itself, you must publish those changes under the same license.

## For maintainers

- Build: `pwsh scripts/build.ps1` (Release, `netstandard2.0`).
- Pack locally: `dotnet pack src/SMBLibrary/SMBLibrary.csproj -c Release -o out`.
- Release: raise `<Version>` in `src/SMBLibrary/SMBLibrary.csproj`, commit, then push the tag `v<Version>`, for example `v1.5.7-nomercy.2`. The `publish` workflow packs, checks that both assemblies are in the package and that the tag matches the version, then pushes to nuget.org with Trusted Publishing. No API key is stored anywhere.
