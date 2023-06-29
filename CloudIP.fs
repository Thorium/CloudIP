namespace CloudIP

module GetIPList =
    open System
    open System.IO
    open System.Net

    let fetch (url : Uri) = 
        let req = WebRequest.Create (url) :?> HttpWebRequest
        use stream = req.GetResponse().GetResponseStream()
        use reader = new StreamReader(stream)
        reader.ReadToEnd()

// http://fssnip.net/8K/title/ipv4-conversion-snippet
module IP_Parsing =    
  open System
  open System.Net

  let intOfIp (s : string) = 
    IPAddress.Parse(s.Trim()).GetAddressBytes() 
    |> Array.rev
    |> fun e -> BitConverter.ToUInt32 (e, 0)
    
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
    
    ipArrayOfIntRange start finish
    
  (* "192.168.1.1/24" -> ["192.168.1.1 .. 192.168.1.254"] *)
  let ipsOfCidrs (d : string) =
    let elem  = slice d [|"/"|]
  
    let lsn x = (1 <<< 32 - x) - 1 |> (~~~)    |> uint32
    let cidr  = Array.get elem 1   |> int
    let mask  = cidr |> int        |> lsn
    let addr  = elem |> Seq.head   |> intOfIp  |> (&&&) mask
    let start,finish = addr + 1u, addr + ~~~mask - 1u

    if cidr > 30 then [| elem |> Seq.head |]
    else
      ipArrayOfIntRange start finish


  // Some additions, making large arrays would be too slow

  let uintsOfCidrs (d : string) =
    let elem  = slice d [|"/"|]
    
    let lsn x = (1 <<< 32 - x) - 1 |> (~~~)    |> uint32
    let cidr  = Array.get elem 1   |> int
    let mask  = cidr |> int        |> lsn
    let addr  = elem |> Seq.head   |> intOfIp  |> (&&&) mask
    let start,finish = addr + 1u, addr + ~~~mask - 1u

    if cidr > 30 then 
      addr, addr
    else
      start, finish

  let isWithinRange ip (ranges:(uint32*uint32)[]) =
    let i = intOfIp ip
    ranges |> Array.exists(fun (start, finish) -> i >= start && i <= finish)

type SupportedCloudServices =
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
        |]

    let fastlyCDN = 
        let ranges = FastlyData.Load "https://api.fastly.com/public-ip-list"
        let ipv4s = ranges.Addresses |> Array.map IP_Parsing.uintsOfCidrs
        ipv4s

    let cloudFlares =
        let ipsFile = Uri "https://www.cloudflare.com/ips-v4"
        let data = GetIPList.fetch ipsFile
        let ip_list = data.Replace("\r", "").Split('\n') |> Array.filter(String.IsNullOrEmpty >> not)
        ip_list 
        |> Array.filter(fun ipv4 -> ipv4.Contains(".")) // For now, IPv4 only
        |> Array.map IP_Parsing.uintsOfCidrs

    let aws =
        let data = AWSDAta.Load "https://ip-ranges.amazonaws.com/ip-ranges.json"
        let ranges = 
            data.Prefixes 
            |> Array.map(fun prefix -> prefix.IpPrefix)
            |> Array.distinct
        let ipv4s = 
            ranges // Will take a while, there are like 5M of them
            |> Array.map IP_Parsing.uintsOfCidrs
        ipv4s |> Array.distinct

    let gitHub =
        let data = GithubData.Load "https://api.github.com/meta"
        let ranges = 
            Array.concat [
                data.Actions;
                data.Web;
                data.Pages;
                data.Api;
            ] |> Array.distinct
        let ipv4s = 
            ranges |> Array.map IP_Parsing.uintsOfCidrs |> Array.distinct
        ipv4s

    let checkIp(ip:string) =
        if String.IsNullOrWhiteSpace ip || ip.Length < 3 || ip.Length > 15 || not(ip.Contains ".") then
            // Not supported IP
            false, None
        else

        if (localIps |> IP_Parsing.isWithinRange ip) || ip = "::1" then
            true, Some LocalIp
        elif cloudFlares |> IP_Parsing.isWithinRange ip then
            true, Some CloudFlare
        elif fastlyCDN |> IP_Parsing.isWithinRange ip then
            true, Some Fastly
        elif aws |> IP_Parsing.isWithinRange ip then
            true, Some AWS
        elif gitHub |> IP_Parsing.isWithinRange ip then
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
    //        let checkedIps = checkIps argv
    //        checkedIps |> Array.iter(fun res -> printfn "%O" res)
    //        0

