# Cloud IP #

This is a project that checks if an IP is within a known IP-address range of cloud service providers.

The intention of this library is just to gather data of user behaviour.

If you think security-wise, a firewall rule is probably a better option.
Or buy the DNS/WHOIS lookup database records.

Currently supported IP-address ranges to identify:

- LocalIp
- CloudFlare
- Fastly
- AWS
- GitHub

The principle of this library is:
- Collect the latest ip-address ranges file (CIDR routing tables) from the provider
- Check if your given IP matches within that range.

### NET 8.0

- Supports both IPv4 and IPv6 via System.Net.IPNetwork.

### NET Standard 2.0 (and .NET Framework)

- Supports IPv4. 
- Maps IPv6 to IPv4.

## Usage

Usage:
```fsharp
// Single:
let found, provider = CloudIP.Cloudservices.checkIp "192.168.1.0"

// Multiple:
let checkedIps = CloudIP.Cloudservices.checkIps [| "123.123.123.123"; "173.245.48.15" |]
checkedIps |> Array.iter(fun res -> printfn "%O" res)

```

Nuget: https://www.nuget.org/packages/CloudIP/
