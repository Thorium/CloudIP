namespace CloudIP

module GetIPList =
    open System
    open System.Diagnostics
    open System.IO
    open System.Net.Http

    let private httpClient = new HttpClient()
    let private azureDownloadPage = Uri "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
    let private cacheDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CloudIP")
    let private azureUrlPrefix = "https://download.microsoft.com/download/"
    let private azureUrlSuffix = "/ServiceTags_Public_"
    let private azureJsonExtension = ".json"

    let fetch (url: Uri) =
        task { return! httpClient.GetStringAsync(url) }

    let private getCachePath fileName =
        Directory.CreateDirectory(cacheDirectory) |> ignore
        Path.Combine(cacheDirectory, fileName)

    let private writeCache fileName (contents: string) =
        let cachePath = getCachePath fileName
        File.WriteAllText(cachePath, contents)
        contents

    let readCache fileName =
        let cachePath = getCachePath fileName

        if File.Exists cachePath then
            Some (File.ReadAllText cachePath)
        else
            None

    let fetchAndCache fileName (url: Uri) =
        task {
            let! contents = fetch url
            return writeCache fileName contents
        }

    let traceFailure providerName (ex: exn) =
        Trace.TraceWarning("CloudIP provider '{0}' load failed: {1}", providerName, ex.Message)

    let fetchAzureServiceTagsUrl () =
        task {
            let! page = fetch azureDownloadPage

            let startIndex = page.IndexOf(azureUrlPrefix, StringComparison.OrdinalIgnoreCase)

            let maybeUrl =
                if startIndex < 0 then
                    None
                else
                    let suffixIndex = page.IndexOf(azureUrlSuffix, startIndex, StringComparison.OrdinalIgnoreCase)

                    if suffixIndex < 0 then
                        None
                    else
                        let extensionIndex = page.IndexOf(azureJsonExtension, suffixIndex, StringComparison.OrdinalIgnoreCase)

                        if extensionIndex < 0 then
                            None
                        else
                            let urlLength = extensionIndex + azureJsonExtension.Length - startIndex
                            Some (Uri(page.Substring(startIndex, urlLength)))

            match maybeUrl with
            | Some url -> return url
            | None -> return invalidOp "Could not locate Azure Service Tags download URL."
        }

    let fetchAzureServiceTagsJson cacheFileName =
        task {
            let! downloadUrl = fetchAzureServiceTagsUrl ()
            return! fetchAndCache cacheFileName downloadUrl
        }

module IP_Parsing =
    open System
    open System.Net
    open System.Net.Sockets

    type IPNetworkFamily =
        | IPv4 = 0
        | IPv6 = 1

    [<Struct>]
    type ParsedIp =
        {
            Family: IPNetworkFamily
            High: uint64
            Low: uint64
        }

    [<Struct>]
    type ParsedRange =
        {
            Family: IPNetworkFamily
            StartHigh: uint64
            StartLow: uint64
            EndHigh: uint64
            EndLow: uint64
        }

    let private maxIpv4 = 0xFFFFFFFFUL

    let private uint64OfBytes (bytes: byte array) offset =
        [| 0 .. 7 |]
        |> Array.fold (fun acc i -> (acc <<< 8) ||| uint64 bytes[offset + i]) 0UL

    let private normalizeAddress (address: IPAddress) =
        if address.IsIPv4MappedToIPv6 then address.MapToIPv4()
        else address

    let parseIpAddress (address: IPAddress) =
        let normalized = normalizeAddress address

        match normalized.AddressFamily with
        | AddressFamily.InterNetwork ->
            let bytes = normalized.GetAddressBytes()
            let low =
                (uint64 bytes[0] <<< 24)
                ||| (uint64 bytes[1] <<< 16)
                ||| (uint64 bytes[2] <<< 8)
                ||| uint64 bytes[3]

            { Family = IPNetworkFamily.IPv4; High = 0UL; Low = low }
        | AddressFamily.InterNetworkV6 ->
            let bytes = normalized.GetAddressBytes()
            { Family = IPNetworkFamily.IPv6; High = uint64OfBytes bytes 0; Low = uint64OfBytes bytes 8 }
        | _ ->
            invalidArg "address" "Unsupported address family."

    let tryParseIp (value: string) =
        if String.IsNullOrWhiteSpace value then
            ValueNone
        else
            match IPAddress.TryParse(value.Trim()) with
            | true, address -> ValueSome (parseIpAddress address)
            | _ -> ValueNone

    let private compare128 leftHigh leftLow rightHigh rightLow =
        if leftHigh < rightHigh then -1
        elif leftHigh > rightHigh then 1
        elif leftLow < rightLow then -1
        elif leftLow > rightLow then 1
        else 0

    let parseCidr (value: string) =
        let parts = value.Trim().Split([| '/' |], StringSplitOptions.RemoveEmptyEntries)

        if parts.Length <> 2 then
            invalidArg "value" "CIDR must contain a prefix length."

        let prefixLength = Int32.Parse(parts[1].Trim())
        let parsedIp = IPAddress.Parse(parts[0].Trim()) |> parseIpAddress
        let family = parsedIp.Family
        let high = parsedIp.High
        let low = parsedIp.Low

        match family with
        | IPNetworkFamily.IPv4 ->
            if prefixLength < 0 || prefixLength > 32 then
                invalidArg "value" "Invalid IPv4 prefix length."

            let mask =
                (~~~((1UL <<< (32 - prefixLength)) - 1UL)) &&& maxIpv4

            let startLow = low &&& mask
            let endLow = startLow ||| (~~~mask &&& maxIpv4)
            { Family = family; StartHigh = 0UL; StartLow = startLow; EndHigh = 0UL; EndLow = endLow }
        | IPNetworkFamily.IPv6 ->
            if prefixLength < 0 || prefixLength > 128 then
                invalidArg "value" "Invalid IPv6 prefix length."

            match prefixLength with
            | 0 ->
                { Family = family; StartHigh = 0UL; StartLow = 0UL; EndHigh = UInt64.MaxValue; EndLow = UInt64.MaxValue }
            | prefix when prefix < 64 ->
                let hostBits = 64 - prefix
                let highMask = ~~~((1UL <<< hostBits) - 1UL)
                let startHigh = high &&& highMask
                let endHigh = startHigh ||| ~~~highMask
                { Family = family; StartHigh = startHigh; StartLow = 0UL; EndHigh = endHigh; EndLow = UInt64.MaxValue }
            | 64 ->
                { Family = family; StartHigh = high; StartLow = 0UL; EndHigh = high; EndLow = UInt64.MaxValue }
            | prefix ->
                let hostBits = 128 - prefix
                let lowMask =
                    if hostBits = 0 then UInt64.MaxValue
                    else ~~~((1UL <<< hostBits) - 1UL)

                let startLow = low &&& lowMask
                let endLow = startLow ||| ~~~lowMask
                { Family = family; StartHigh = high; StartLow = startLow; EndHigh = high; EndLow = endLow }
        | _ ->
            invalidArg "value" "Unsupported address family."

    let parseCidrs (values: string array) =
        values
        |> Array.filter (String.IsNullOrWhiteSpace >> not)
        |> Array.map parseCidr
        |> Array.distinct

    let isWithinRange (ip: ParsedIp) (ranges: ParsedRange array) =
        ranges
        |> Array.exists (fun (range: ParsedRange) ->
            range.Family = ip.Family
            && compare128 range.StartHigh range.StartLow ip.High ip.Low <= 0
            && compare128 ip.High ip.Low range.EndHigh range.EndLow <= 0)

type SupportedCloudServices =
    | InvalidIp
    | LocalIp
    | CloudFlare
    | Fastly
    | AWS
    | GitHub
    | GoogleCloud
    | Azure
    | OracleCloud

type internal FastlyData = FSharp.Data.JsonProvider<"https://api.fastly.com/public-ip-list">
type internal AwsData = FSharp.Data.JsonProvider<"https://ip-ranges.amazonaws.com/ip-ranges.json">
type internal GithubData = FSharp.Data.JsonProvider<"https://api.github.com/meta">
type internal GoogleCloudData = FSharp.Data.JsonProvider<"https://www.gstatic.com/ipranges/cloud.json">
type internal AzureData = FSharp.Data.JsonProvider<"""{ "values": [ { "name": "AzureCloud", "properties": { "addressPrefixes": [ "1.1.1.0/24" ] } } ] }""">
type internal OracleCloudData = FSharp.Data.JsonProvider<"""{ "regions": [ { "cidrs": [ { "cidr": "1.1.1.0/24", "tags": [ "OCI" ] } ] } ] }""">

module Cloudservices =

    open System

    type private ProviderRanges =
        {
            CloudFlare: IP_Parsing.ParsedRange array
            Fastly: IP_Parsing.ParsedRange array
            AWS: IP_Parsing.ParsedRange array
            GitHub: IP_Parsing.ParsedRange array
            GoogleCloud: IP_Parsing.ParsedRange array
            Azure: IP_Parsing.ParsedRange array
            OracleCloud: IP_Parsing.ParsedRange array
        }

    let private emptyRanges : IP_Parsing.ParsedRange array = [||]
    let private cloudflareCacheV4 = "cloudflare-ips-v4.txt"
    let private cloudflareCacheV6 = "cloudflare-ips-v6.txt"
    let private fastlyCache = "fastly-public-ip-list.json"
    let private awsCache = "aws-ip-ranges.json"
    let private githubCache = "github-meta.json"
    let private googleCloudCache = "google-cloud.json"
    let private azureCache = "azure-service-tags.json"
    let private oracleCloudCache = "oracle-cloud.json"

    let localIps =
        [|
            "10.0.0.0/8"
            "127.0.0.0/8"
            "169.254.0.0/16"
            "172.16.0.0/12"
            "192.168.0.0/16"
            "::1/128"
            "fc00::/7"
            "fe80::/10"
        |]
        |> IP_Parsing.parseCidrs

    let private safeLoad providerName loader =
        task {
            try
                return! loader ()
            with ex ->
                GetIPList.traceFailure providerName ex
                return emptyRanges
        }

    let private loadCachedText cacheFileName parse =
        match GetIPList.readCache cacheFileName with
        | Some cached -> parse cached
        | None -> emptyRanges

    let private loadCachedJson cacheFileName parse =
        loadCachedText cacheFileName parse

    let getFastlyCDN () =
        task {
            let parse contents =
                let data = FastlyData.Parse contents

                // Fastly publishes very broad IPv6 allocations, so keep this provider IPv4-only for now.
                data.Addresses
                |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAndCache fastlyCache (Uri "https://api.fastly.com/public-ip-list")
                return parse contents
            with ex ->
                GetIPList.traceFailure "Fastly" ex
                return loadCachedJson fastlyCache parse
        }

    let getCloudFlares () =
        task {
            let parse (data4: string) (data6: string) =
                [| data4; data6 |]
                |> Array.filter (String.IsNullOrWhiteSpace >> not)
                |> Array.collect (fun data -> data.Replace("\r", "").Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries))
                // Keep Cloudflare IPv6 because the published edge ranges are specific enough for this library's heuristic use.
                |> IP_Parsing.parseCidrs

            try
                let data4Task = GetIPList.fetchAndCache cloudflareCacheV4 (Uri "https://www.cloudflare.com/ips-v4")
                let data6Task = GetIPList.fetchAndCache cloudflareCacheV6 (Uri "https://www.cloudflare.com/ips-v6")
                let! data4 = data4Task
                let! data6 = data6Task
                return parse data4 data6
            with ex ->
                GetIPList.traceFailure "CloudFlare" ex
                match GetIPList.readCache cloudflareCacheV4, GetIPList.readCache cloudflareCacheV6 with
                | Some data4, Some data6 -> return parse data4 data6
                | Some data4, None -> return parse data4 String.Empty
                | None, Some data6 -> return parse String.Empty data6
                | _ -> return emptyRanges
        }

    let getAws () =
        task {
            let parse contents =
                let data = AwsData.Parse contents

                // AWS IPv6 ranges are intentionally broad, so leave AWS detection IPv4-only until there is a narrower policy.
                data.Prefixes
                |> Array.map (fun prefix -> prefix.IpPrefix)
                |> Array.distinct
                |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAndCache awsCache (Uri "https://ip-ranges.amazonaws.com/ip-ranges.json")
                return parse contents
            with ex ->
                GetIPList.traceFailure "AWS" ex
                return loadCachedJson awsCache parse
        }

    let getGitHub () =
        task {
            let parse contents =
                let data = GithubData.Parse contents

                Array.concat [
                    data.Web
                    data.Api
                    data.Git
                    data.Pages
                    data.Hooks
                ]
                |> Array.distinct
                |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAndCache githubCache (Uri "https://api.github.com/meta")
                return parse contents
            with ex ->
                GetIPList.traceFailure "GitHub" ex
                return loadCachedJson githubCache parse
        }

    let getGoogleCloud () =
        task {
            let parse contents =
                let data = GoogleCloudData.Parse contents

                // Use Google's cloud.json feed, but keep it IPv4-only for now to avoid overly broad IPv6 classification.
                data.Prefixes
                |> Array.collect (fun prefix ->
                    [|
                        match prefix.Ipv4Prefix with
                        | Some value -> yield value
                        | None -> ()
                    |])
                |> Array.distinct
                |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAndCache googleCloudCache (Uri "https://www.gstatic.com/ipranges/cloud.json")
                return parse contents
            with ex ->
                GetIPList.traceFailure "GoogleCloud" ex
                return loadCachedJson googleCloudCache parse
        }

    let getAzure () =
        task {
            let parse contents =
                let data = AzureData.Parse contents

                data.Values
                |> Array.tryFind (fun value -> value.Name = "AzureCloud")
                |> function
                    | None -> emptyRanges
                    | Some value ->
                        // AzureCloud keeps the meaning narrow: generic Azure public cloud hosting, not every Microsoft service tag.
                        value.Properties.AddressPrefixes
                        |> Array.filter (fun prefix -> prefix.Contains ".")
                        |> Array.distinct
                        |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAzureServiceTagsJson azureCache
                return parse contents
            with ex ->
                GetIPList.traceFailure "Azure" ex
                return loadCachedJson azureCache parse
        }

    let getOracleCloud () =
        task {
            let parse contents =
                let data = OracleCloudData.Parse contents

                data.Regions
                |> Array.collect (fun region -> region.Cidrs)
                |> Array.filter (fun cidr -> cidr.Tags |> Array.exists ((=) "OCI"))
                |> Array.map (fun cidr -> cidr.Cidr)
                |> Array.distinct
                |> IP_Parsing.parseCidrs

            try
                let! contents = GetIPList.fetchAndCache oracleCloudCache (Uri "https://docs.oracle.com/iaas/tools/public_ip_ranges.json")
                return parse contents
            with ex ->
                GetIPList.traceFailure "OracleCloud" ex
                return loadCachedJson oracleCloudCache parse
        }

    let private providerRanges =
        lazy (
            task {
                let cloudFlareTask = safeLoad "CloudFlare" getCloudFlares
                let fastlyTask = safeLoad "Fastly" getFastlyCDN
                let awsTask = safeLoad "AWS" getAws
                let gitHubTask = safeLoad "GitHub" getGitHub
                let googleCloudTask = safeLoad "GoogleCloud" getGoogleCloud
                let azureTask = safeLoad "Azure" getAzure
                let oracleCloudTask = safeLoad "OracleCloud" getOracleCloud

                let! cloudFlare = cloudFlareTask
                let! fastly = fastlyTask
                let! aws = awsTask
                let! gitHub = gitHubTask
                let! googleCloud = googleCloudTask
                let! azure = azureTask
                let! oracleCloud = oracleCloudTask

                return {
                    CloudFlare = cloudFlare
                    Fastly = fastly
                    AWS = aws
                    GitHub = gitHub
                    GoogleCloud = googleCloud
                    Azure = azure
                    OracleCloud = oracleCloud
                }
            })

    let private getProviderRanges () =
        providerRanges.Value.GetAwaiter().GetResult()

    let checkIp ip =
        match IP_Parsing.tryParseIp ip with
        | ValueNone -> false, Some InvalidIp
        | ValueSome parsedIp ->
            if localIps |> IP_Parsing.isWithinRange parsedIp then
                true, Some LocalIp
            else
                let ranges = getProviderRanges ()

                if ranges.CloudFlare |> IP_Parsing.isWithinRange parsedIp then
                    true, Some CloudFlare
                elif ranges.Fastly |> IP_Parsing.isWithinRange parsedIp then
                    true, Some Fastly
                elif ranges.GitHub |> IP_Parsing.isWithinRange parsedIp then
                    true, Some GitHub
                elif ranges.GoogleCloud |> IP_Parsing.isWithinRange parsedIp then
                    true, Some GoogleCloud
                elif ranges.Azure |> IP_Parsing.isWithinRange parsedIp then
                    true, Some Azure
                elif ranges.AWS |> IP_Parsing.isWithinRange parsedIp then
                    true, Some AWS
                elif ranges.OracleCloud |> IP_Parsing.isWithinRange parsedIp then
                    true, Some OracleCloud
                else
                    false, None

    let checkIps ips =
        ips |> Array.map (fun i -> i, checkIp i)

    //[<EntryPoint>]
    //let main argv =
    //    if argv |> Array.isEmpty then
    //        printfn "Usage: CloudIP 123.123.123.123"
    //        0
    //    else
    //        printfn "Checking IP(s)..."
    //        let sw = System.Diagnostics.Stopwatch.StartNew()
    //        let checkedIps = checkIps argv
    //        checkedIps |> Array.iter(fun res -> printfn "%O" res)
    //        sw.Stop()
    //        printfn "%O" sw.Elapsed.TotalMilliseconds
    //        0

