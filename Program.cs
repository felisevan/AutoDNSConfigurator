using System.Runtime.InteropServices;
using System.Text.Json;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using Windows.Win32;
using Microsoft.Management.Infrastructure;

public enum SetDNSServerSearchOrderErrorCode
{
    SuccessfulCompletionNoRebootRequired = 0,
    SuccessfulCompletionRebootRequired = 1,
    MethodNotSupportedOnPlatform = 64,
    UnknownFailure = 65,
    InvalidSubnetMask = 66,
    ErrorOccurredProcessingInstance = 67,
    InvalidInputParameter = 68,
    MoreThanFiveGatewaysSpecified = 69,
    InvalidIPAddress = 70,
    InvalidGatewayIPAddress = 71,
    ErrorOccurredAccessingRegistry = 72,
    InvalidDomainName = 73,
    InvalidHostName = 74,
    NoPrimarySecondaryWINSServerDefined = 75,
    InvalidFile = 76,
    InvalidSystemPath = 77,
    FileCopyFailed = 78,
    InvalidSecurityParameter = 79,
    UnableToConfigureTCPIPService = 80,
    UnableToConfigureDHCPService = 81,
    UnableToRenewDHCPLease = 82,
    UnableToReleaseDHCPLease = 83,
    IPNotEnabledOnAdapter = 84,
    IPXNotEnabledOnAdapter = 85,
    FrameNetworkNumberBoundsError = 86,
    InvalidFrameType = 87,
    InvalidNetworkNumber = 88,
    DuplicateNetworkNumber = 89,
    ParameterOutOfBounds = 90,
    AccessDenied = 91,
    OutOfMemory = 92,
    AlreadyExists = 93,
    PathFileOrObjectNotFound = 94,
    UnableToNotifyService = 95,
    UnableToNotifyDNSService = 96,
    InterfaceNotConfigurable = 97,
    NotAllDHCPLeasesReleasedRenewed = 98,
    DHCPNotEnabledOnAdapter = 100,
    Other = 101
}


public enum SendARPErrorCode
{
    ERROR_BAD_NET_NAME = 67,
    ERROR_BUFFER_OVERFLOW = 111,
    ERROR_GEN_FAILURE = 31,
    ERROR_INVALID_PARAMETER = 87,
    ERROR_INVALID_USER_BUFFER = 1784,
    ERROR_NOT_FOUND = 1168,
    ERROR_NOT_SUPPORTED = 50
}


class MatchPair
{
    public string TargetMACAddress { get; set; }
    public string[] TargetDNSList { get; set; }
}

class Program
{

    static IEnumerable<(IPAddress InterfaceIPAddress, PhysicalAddress InterfacePhysicalAddress, IPAddress GatewayIPAddress, PhysicalAddress GatewayPhysicalAddress)> GetInterfaceAndGatewayInformation()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(ni => (
                InterfaceIPAddress: ni.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork)?.Address,
                InterfacePhysicalAddress: ni.GetPhysicalAddress(),
                GatewayIPAddress: ni.GetIPProperties().GatewayAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork)?.Address
            ))
            .Where(ni => ni.InterfaceIPAddress != null && ni.GatewayIPAddress != null)
            .Select(ni => (ni.InterfaceIPAddress, ni.InterfacePhysicalAddress, ni.GatewayIPAddress,
                GatewayPhysicalAddress: ConvertIPtoMAC(ni.InterfaceIPAddress, ni.GatewayIPAddress)
            ));
    }


    static PhysicalAddress ConvertIPtoMAC(IPAddress IpAddress, IPAddress GatewayAddress)
    {
        var destIp = BitConverter.ToUInt32(GatewayAddress.GetAddressBytes(), 0);
        var srcIp = BitConverter.ToUInt32(IpAddress.GetAddressBytes(), 0);
        var addr = new byte[6];
        uint addr_len = (uint)addr.Length;

        GCHandle handle = GCHandle.Alloc(addr, GCHandleType.Pinned);
        try
        {
            IntPtr buffer = handle.AddrOfPinnedObject();

            uint result = 0;
            unsafe { result = PInvoke.SendARP(destIp, srcIp, (void*)buffer, ref addr_len); }
            if (result == 0)
            {
                byte[] macAddrBytes = new byte[addr_len];
                Marshal.Copy(buffer, macAddrBytes, 0, (int)addr_len);
                return new PhysicalAddress(macAddrBytes);
            }
            else
            {
                throw new InvalidOperationException($"SendARP failed: {Enum.GetName(typeof(SendARPErrorCode), result)}");
            }
        }
        finally
        {
            handle.Free();
        }
    }

    static uint SetDNS(PhysicalAddress GatewayPhysicalAddress, string[] DNSArray)
    {
        var targetMACAddress = string.Join(":", GatewayPhysicalAddress.GetAddressBytes().Select(b => b.ToString("X2")));
        var session = CimSession.Create(null); ;
        var param = new CimMethodParametersCollection
        {
            CimMethodParameter.Create("DNSServerSearchOrder", DNSArray, CimFlags.In)
        };
        var instance = session.QueryInstances(@"root/cimv2", "WQL", $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE MACAddress = '{targetMACAddress}'").First();
        var result = session.InvokeMethod(instance, "SetDNSServerSearchOrder", param);
        return (uint)result.ReturnValue.Value;
    }
    
    

    static void Main()
    {
        string jsonFilePath = "rules.json";
        string jsonString = File.ReadAllText(jsonFilePath);

        var rules = JsonSerializer.Deserialize<List<MatchPair>>(jsonString).ToDictionary(t => PhysicalAddress.Parse(t.TargetMACAddress), t => t.TargetDNSList);

        foreach (var i in GetInterfaceAndGatewayInformation())
        {
            Console.WriteLine(i.ToString());
           if (rules.ContainsKey(i.GatewayPhysicalAddress))
            {
                Console.WriteLine($"{i.GatewayPhysicalAddress}: {String.Join(", ", rules[i.GatewayPhysicalAddress])}");
                var result = SetDNS(i.InterfacePhysicalAddress, rules[i.GatewayPhysicalAddress]);
                if (result != 0)
                {
                    Console.WriteLine($"SetDNSServerSearchOrder failed: {Enum.GetName(typeof(SetDNSServerSearchOrderErrorCode), result)}");
                }
            }
        }
    }
}