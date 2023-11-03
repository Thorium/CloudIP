namespace CloudIP

module GetIPList =
    open System
    open System.IO
    open System.Net

    let fetch (url : Uri) =
        task {
            let req = WebRequest.Create (url) :?> HttpWebRequest
            let! resp = req.GetResponseAsync()
            use stream = resp.GetResponseStream()
            use reader = new StreamReader(stream)
            return reader.ReadToEnd()
        }
// http://fssnip.net/8K/title/ipv4-conversion-snippet
module IP_Parsing =
  open System
  open System.Net

  [<Struct>]
  type IPvNetwrok =
  | IPv4 = 0
 // No native support yet, would require uint128:
  | IPv6 = 1


  let intOfIp (s : string) =
    let parsed = IPAddress.Parse(s.Trim())

    match parsed.AddressFamily with
    | System.Net.Sockets.AddressFamily.InterNetworkV6 ->
        // IPv6 is 128bit. For now, we just map it to IPv4.
        let convertedIpV4 = parsed.MapToIPv4()
        let i =
            convertedIpV4.GetAddressBytes()
            |> Array.rev
            |> fun e -> BitConverter.ToUInt32 (e, 0)
        struct (IPvNetwrok.IPv4, i)
    | _ (* System.Net.Sockets.AddressFamily.InterNetwork *) ->
        let i = 
            parsed.GetAddressBytes()
            |> Array.rev
            |> fun e -> BitConverter.ToUInt32 (e, 0)
        struct (IPvNetwrok.IPv4, i)
    
  let ipOfInt (d : uint32) = 
    BitConverter.GetBytes d
    |> Array.rev
    |> IPAddress
    |> string

  let slice (d : string) (iden : string array) = 
    d.Split(iden, StringSplitOptions.None)

  let ipArrayOfIntRange start finish =
    [| for i in start .. finish -> ipOfInt i |]

  let ipsOfRange (d : string) = 
    let elem = slice d [|"to"; "-"; "and"|]
    let start,finish = intOfIp elem.[0], intOfIp elem.[1]
    match intOfIp elem.[0], intOfIp elem.[1] with
    | (ipvType1, start), (ipvType2, finish) when ipvType1 = ipvType2 -> ipvType1, ipArrayOfIntRange start finish
    | _ -> IPvNetwrok.IPv4, Array.empty // no mixed networks
    
  (* "192.168.1.1/24" -> ["192.168.1.1 .. 192.168.1.254"] *)
  let ipsOfCidrs (d : string) =
    let elem  = slice d [|"/"|]
  
    let lsn x = (1 <<< 32 - x) - 1 |> (~~~)    |> uint32
    let cidr  = Array.get elem 1   |> int
    let mask  = cidr |> int        |> lsn
    let struct(ipvn, ipOfInt) = elem |> Seq.head |> intOfIp
    let addr  = ipOfInt |> (&&&) mask
    let start,finish = addr + 1u, addr + ~~~mask - 1u

    let limit = match ipvn with | IPvNetwrok.IPv4 -> 30 | _ -> 60

    if cidr > limit then ipvn, [| elem |> Seq.head |]
    else ipvn, ipArrayOfIntRange start finish


  // Some additions, making large arrays would be too slow

  let uintsOfCidrs (d : string) =
    let elem  = slice d [|"/"|]
    
    let lsn x = (1 <<< 32 - x) - 1 |> (~~~)    |> uint32
    let cidr  = Array.get elem 1   |> int
    let mask  = cidr |> int        |> lsn
    let struct(ipvn, ipOfInt) = elem |> Seq.head |> intOfIp
    let addr  = ipOfInt |> (&&&) mask
    let start,finish = addr + 1u, addr + ~~~mask - 1u
    let limit = match ipvn with | IPvNetwrok.IPv4 -> 30 | _ -> 60

    if cidr > limit then struct(ipvn, addr, addr)
    else struct(ipvn, start, finish)

  let isWithinRange itm (ranges:struct(IPvNetwrok*uint32*uint32) Set) =
    let struct(checkNtwrk, ipAsInt) = itm
    ranges |> Set.exists(fun struct(nwrk, start, finish) -> nwrk = checkNtwrk && ipAsInt >= start && ipAsInt <= finish)
    

type SupportedCloudServices =
| InvalidIp
| LocalIp
| CloudFlare
| Fastly
| AWS
| GitHub
// Todo, add services...

//| Azure       https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20210607.json // Will they change the file?
//| Google      https://www.gstatic.com/ipranges/goog.json // Is this correct file?
//| Rackspace
//| IBM         https://cloud.ibm.com/docs/hardware-firewall-dedicated?topic=hardware-firewall-dedicated-ibm-cloud-ip-ranges
//| Github      https://api.github.com/meta

//  #r @"...\packages\fsharp.data\4.1.1\lib\netstandard2.0\FSharp.Data.dll";;

type FastlyData = FSharp.Data.JsonProvider<"https://api.fastly.com/public-ip-list">
type AWSDAta = FSharp.Data.JsonProvider<"https://ip-ranges.amazonaws.com/ip-ranges.json">
//type AzureData = FSharp.Data.JsonProvider<"https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20210607.json">
type GithubData = FSharp.Data.JsonProvider<"https://api.github.com/meta">

module Cloudservices =

    open System
    
    let localIps = 
        [|
            "10.0.0.0/8" |> IP_Parsing.uintsOfCidrs;
            "172.16.0.0/12" |> IP_Parsing.uintsOfCidrs;
            "192.168.0.0/16" |> IP_Parsing.uintsOfCidrs
        |] |> Set.ofArray

    let getFastlyCDN() =
        task {
            let! ranges = FastlyData.AsyncLoad "https://api.fastly.com/public-ip-list" |> Async.StartAsTask
            let ipv4s = ranges.Addresses |> Array.map IP_Parsing.uintsOfCidrs
            //let ipv6s = ranges.Ipv6Addresses |> Array.map IP_Parsing.uintsOfCidrs
            return
                ipv4s //Array.concat [ ipv4s ; ipv6s]
                |> Set.ofArray
        }

    let getCloudFlares() =
        task {
            let! data4 = "https://www.cloudflare.com/ips-v4" |> Uri |> GetIPList.fetch
            let ip_list4 = data4.Replace("\r", "").Split('\n') |> Array.filter(String.IsNullOrEmpty >> not)
            //let data6 = "https://www.cloudflare.com/ips-v6" |> Uri |> GetIPList.fetch
            //let ip_list6 = data6.Replace("\r", "").Split('\n') |> Array.filter(String.IsNullOrEmpty >> not)
            return
                ip_list4 //Array.concat [ ip_list4 ; ip_list6 ]
                |> Array.map IP_Parsing.uintsOfCidrs
                |> Set.ofArray
        }

    let getAws() =
        task {
            let! data = AWSDAta.AsyncLoad "https://ip-ranges.amazonaws.com/ip-ranges.json" |> Async.StartAsTask
            let ranges = 
                data.Prefixes 
                |> Array.map(fun prefix -> prefix.IpPrefix)
                |> Array.distinct
            let ipv4s = 
                ranges // Will take a while, there are like 5M of them
                |> Array.map IP_Parsing.uintsOfCidrs |> Set.ofArray
            return ipv4s
        }

    let getGitHub() =
        task {
            let! data = GithubData.AsyncLoad "https://api.github.com/meta" |> Async.StartAsTask
            let ranges = 
                Array.concat [
                    data.Actions;
                    data.Web;
                    data.Pages;
                    data.Api;
                ] |> Array.distinct
            let ipv4s = 
                ranges |> Array.map IP_Parsing.uintsOfCidrs |> Set.ofArray
            return ipv4s
        }

    let fastlyCDN, cloudFlares, aws, gitHub =
        // Start fetching as parallel:
        let startFastlyCDN = getFastlyCDN()
        let startAws = getAws()
        let startGitHub = getGitHub()
        let startCloudFlares = getCloudFlares()
        async {
            let! fastlyCDN = startFastlyCDN |> Async.AwaitTask
            let! cloudFlares = startCloudFlares |> Async.AwaitTask
            let! aws = startAws |> Async.AwaitTask
            let! gitHub = startGitHub |> Async.AwaitTask
            return fastlyCDN, cloudFlares, aws, gitHub
        } |> Async.RunSynchronously


    let checkIp(ip:string) =
        if String.IsNullOrWhiteSpace ip || ip.Length < 3 || ip.Length > 46 || not(ip.Contains "." || ip.Contains ":") then
            // Not an ip
            false, Some InvalidIp
        else
        if ip = "::1" || ip = "127.0.0.1" then
            // Not supported IP
            true, Some LocalIp
        else

        let ipInt =
            try
                ValueSome (IP_Parsing.intOfIp ip)
            with
            | :? FormatException -> ValueNone

        match ipInt with
        | ValueNone -> true, Some InvalidIp
        | ValueSome uIp ->

            if (localIps |> IP_Parsing.isWithinRange uIp) then
                true, Some LocalIp
            elif cloudFlares |> IP_Parsing.isWithinRange uIp then
                true, Some CloudFlare
            elif fastlyCDN |> IP_Parsing.isWithinRange uIp then
                true, Some Fastly
            elif aws |> IP_Parsing.isWithinRange uIp then
                true, Some AWS
            elif gitHub |> IP_Parsing.isWithinRange uIp then
                true, Some GitHub
            else false, None

    let checkIps(ips:string[]) =
        let res = ips |> Array.map(fun i -> i, checkIp i)
        res

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

