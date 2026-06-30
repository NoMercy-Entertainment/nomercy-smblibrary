# nomercy-smblibrary

NoMercy fork of [SMBLibrary](https://github.com/TalAloni/SMBLibrary) — a pure-C#
SMB 1.0/CIFS, SMB 2.0/2.1 and SMB 3.0 client. Used by `NoMercy.Storage`'s SMB
driver so SMB shares work cross-platform with no native dependency.

**Upstream:** TalAloni/SMBLibrary @ `7742c28` (1.5.7 line)
**License:** LGPL-3.0-or-later (see [src/License.txt](src/License.txt))

## Why a fork

Stock SMBLibrary's public `Connect(IPAddress, SMBTransportType)` hardcodes port
445; the port-taking overload is `protected internal`, so the client can never
reach an SMB server on any other port. The fork promotes that overload to public:

```csharp
bool Connect(IPAddress serverAddress, SMBTransportType transport, int port);
```

on `ISMBClient`, `SMB2Client`, and `SMB1Client`. Nothing else is changed — the
NTLM/NTLMv2 authentication is untouched. The fork narrows the build to a single
`netstandard2.0` assembly (one managed DLL runs on every runtime the media
server targets) and renames the output to `NoMercy.SMBLibrary` so it never
collides with the upstream NuGet package.

## Binaries

The built DLLs live in `output/managed/` and are committed so consumers don't
need to build the fork:

| File | Purpose |
|------|---------|
| output/managed/NoMercy.SMBLibrary.dll | the SMB client |
| output/managed/NoMercy.SMBLibrary.Utilities.dll | its byte/encoding helpers |

`NoMercy.Storage.csproj` references both directly by relative path.

## Rebuilding

```pwsh
pwsh scripts/build.ps1
```

Builds `src/SMBLibrary/SMBLibrary.csproj` (`netstandard2.0`, Release) and copies
the two DLLs into `output/managed/`.
