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
- GoogleCloud
- Azure
- OracleCloud

The principle of this library is:
- Collect the latest ip-address ranges file (CIDR routing tables) from the provider
- Check if your given IP matches within that range.

### IP Support

- Supports both IPv4 and IPv6.
- Uses direct CIDR range matching for both address families.
- Treats local/private IPv4 and IPv6 ranges as `LocalIp`.

### Provider Loading

- Provider ranges are fetched lazily on first use.
- Raw provider feeds are cached on disk in `%LOCALAPPDATA%/CloudIP`.
- The library refreshes provider data from the network on initial load and falls back to the cached copy if that refresh fails.

### Provider Scope

- `GitHub` excludes `actions` to avoid broad Azure-backed runner ranges.
- `GoogleCloud` uses `cloud.json`, not `goog.json`.
- `Azure` uses the `AzureCloud` service tag only.
- `OracleCloud` uses OCI ranges tagged `OCI` only.
- IPv6 stays conservative per provider to avoid overclaiming very broad provider allocations.

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
