using System.Net;
using System.Net.Sockets;
using System.Text;
using HarpoS7;
using HarpoS7.Auth;
using HarpoS7.Extensions;
using HarpoS7.PoC;
using HarpoS7.PoC.Models;
using HarpoS7.PoC.Packets;
using HarpoS7.PublicKeys.Exceptions;
using HarpoS7.PublicKeys.Impl;
using HarpoS7.Transport;
using HarpoS7.Utilities.Auth;
using HarpoS7.Utilities.Extensions;

// The PoC now uses proper data structures for S7 Comm Plus packets
// instead of hardcoded binary blobs. See Protocol/ and Packets/ folders.

var readBuffer = new byte[1024];
if (args.Length < 1 || !IPEndPoint.TryParse(args[0], out var endPoint))
{
    Console.WriteLine("Usage: HarpoS7.PoC ip_address:port [optional access password]");
    Console.WriteLine("Example (no password): HarpoS7.PoC 192.168.1.10:102");
    Console.WriteLine("Example (w. password): HarpoS7.PoC 192.168.1.10:102 \"zaq1@WSX\"");
    
    return;
}

// Connect to the PLC
using var client = new TcpClient();

try
{
	await client.ConnectAsync(endPoint);
}
catch (SocketException ex)
{
	Console.WriteLine($"[-] Could not connect to {endPoint}");
	Console.WriteLine($"[-] Exception message: {ex.Message}");

	return;
}

Console.WriteLine($"[+] Connected to {endPoint}");

// Use CotpStream for proper TPKT/COTP framing
var cotpStream = new CotpStream(client.GetStream());

// COTP Connection Request (using structured CotpStream instead of hardcoded bytes)
Console.WriteLine("Sending COTP CR...");
await cotpStream.WriteConnectionRequestAsync("SIMATIC-ROOT-HMI");

Console.WriteLine("Waiting for COTP Connection Confirm");
await cotpStream.ReadConnectionConfirmAsync();

// Write empty DT-Data
await cotpStream.WriteEmptyDtDataAsync();

// Send S7CommPlus CreateObject request (using structured builder instead of binary blob)
Console.WriteLine("Creating a session object");
var createObjectRequest = new CreateObjectRequest();
cotpStream.Write(createObjectRequest.BuildPayload());

Console.WriteLine("Waiting for create object response");
var responseLength = await cotpStream.ReadAsync(readBuffer);

// Parse the CreateObject response using the structured parser.
// This dynamically scans for the session ID, fingerprint, and challenge
// instead of using hardcoded offsets, which fixes compatibility with
// different PLC models and firmware versions (issue #18).
CreateObjectResponse response;
try
{
    response = new CreateObjectResponse(readBuffer.AsSpan(0, responseLength));
}
catch (InvalidDataException ex)
{
    Console.WriteLine($"[-] Failed to parse CreateObject response: {ex.Message}");
    Console.WriteLine($"[-] Response hex: {Convert.ToHexString(readBuffer.AsSpan(0, responseLength))}");
    return;
}

Console.WriteLine($"Session ID: 0x{response.SessionId:X8}");
Console.WriteLine($"Fingerprint: {response.Fingerprint}");

Console.Write("Challenge: ");
Helpers.PrintBuffer(response.Challenge);

// reverse string and parse fingerprint
var publicKeyFingerprint = new byte[Constants.KeyIdLength];
Helpers.ParseAndReverseBytes(response.Fingerprint, publicKeyFingerprint);

Console.Write("Actual fingerprint: ");
Helpers.PrintBuffer(publicKeyFingerprint);

// get the matching public key from the KeyStore
var store = new DefaultPublicKeyStore();
var publicKey = new byte[store.GetPublicKeyLength(response.Fingerprint)];

try
{
    store.ReadPublicKey(publicKey.AsSpan(), response.Fingerprint);
}
catch (UnknownPublicKeyException)
{
    Console.WriteLine("[-] Public key for this fingerprint was not found in the key store. " +
                      "You need to find the appropriate key and add it to the key store.");
    return;
}

Console.WriteLine("[+] Public key found");

// create buffers
var publicKeyFamily = response.Fingerprint.ToPublicKeyFamily();
var sessionKey = new byte[Constants.SessionKeyLength];
var keyBlob = new byte[response.Fingerprint.StartsWith("03:") ? CommonConstants.EncryptedBlobLengthPlcSim : CommonConstants.EncryptedBlobLengthRealPlc];

Console.WriteLine("Doing the encryption...");

// auth locally
LegacyAuthenticationScheme.Authenticate(
    keyBlob.AsSpan(),
    sessionKey.AsSpan(),
    response.Challenge.AsSpan(),
    publicKey.AsSpan(),
    publicKeyFamily
);

// construct metadata
var pubKeyId = new byte[Constants.KeyIdLength];
var sessionKeyId = new byte[Constants.KeyIdLength];

publicKey.DeriveKeyId(pubKeyId);
sessionKey.DeriveKeyId(sessionKeyId);

var setMultiVarsRequest = new SetMultiVarsRequest(
    pubKeyId,
    sessionKeyId,
    keyBlob.AsSpan(),
    response.SessionId
);

// send request
Console.WriteLine("Sending a set multi vars request");

switch (publicKeyFamily)
{
    case EPublicKeyFamily.S71500:
        setMultiVarsRequest.WriteS71500(client.GetStream());
        break;
    case EPublicKeyFamily.S71200:
        setMultiVarsRequest.WriteS71200(client.GetStream());
        break;
    case EPublicKeyFamily.PlcSim:
        setMultiVarsRequest.WritePlcSim(client.GetStream());
        break;
    default:
        throw new Exception("setMultiVarsRequest: Unsupported public key family");
}

var tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for a set var response...");

int read;
try
{
	read = await client.GetStream().ReadAsync(readBuffer, tokenSource.Token);
}
catch (OperationCanceledException)
{
	Console.WriteLine("[-] No response after 3000 ms - authentication failed");
	return;
}

if (read <= 0)
{
	Console.WriteLine("[-] The PLC sent an empty response");
	return;
}

// an approximation of the return value field (should be all 0x00).
// I might have included the integrity id field or the unknown field by accident;
// these should be all 0x00 anyway.
const int returnValueOffset = 0x15;
const int returnValueLength = 7;
for (var i = returnValueOffset; i < returnValueOffset + returnValueLength; ++i)
{
	if (readBuffer[i] != 0x00)
	{
		Console.WriteLine("[-] Looks like an error has occured. Check if the ReturnValue field is 0x00 (OK)");
		return;
	}
}

Helpers.UseColor(() =>
{
    Console.WriteLine("[++] Success! Looks like the authentication was successful. Check the packet dump (e.g. in Wireshark) to be sure.");
}, ConsoleColor.Green);

if (args.Length <= 1)
{
    return;
}
if (publicKeyFamily != EPublicKeyFamily.S71200 && publicKeyFamily != EPublicKeyFamily.S71500)
{
    Console.WriteLine("[-] Legitimation is currently only supported on S7-1200s and S7-1500s");
    return;
}

var accessPassword = args[1];
Console.WriteLine($"Trying to legitimate the session with a password (\"{accessPassword}\")");

Console.WriteLine("Requesting the legitimation challenge");
var subStreamRequest = new GetVarSubStreamedRequest(sessionKey.AsSpan(), response.SessionId);
subStreamRequest.WriteRealPlc(client.GetStream());

tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for the challenge...");

try
{
    read = await client.GetStream().ReadAsync(readBuffer, tokenSource.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("[-] No response after 3000 ms - legitimation failed");
    return;
}

const int realPlcLegitimationChallengeOffset = 0x3B;
var legitimationChallenge = readBuffer.AsSpan(realPlcLegitimationChallengeOffset, 20).ToArray();

Console.Write("[+] Legitimation challenge: ");
Helpers.PrintBuffer(legitimationChallenge);

Console.WriteLine("Solving the legitimation challenge...");

var legitBlob = new byte[CommonConstants.EncryptedLegitimationBlobLengthRealPlc]; 
LegitimateScheme.SolveLegitimateChallengeRealPlc(
    legitBlob.AsSpan(),
    legitimationChallenge.AsSpan(),
    publicKey.AsSpan(),
    publicKeyFamily,
    sessionKey.AsSpan(),
    accessPassword
);

Console.WriteLine("[+] Challenge solved");
Console.WriteLine("Sending the SetVarSubStreamed request...");

var legitSetChallenge = new SetVarSubStreamedRequest(sessionKey, legitBlob, response.SessionId);
legitSetChallenge.WriteRealPlc(client.GetStream());

await cotpStream.WriteEmptyDtDataAsync();

tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for the response...");

try
{
    read = await client.GetStream().ReadAsync(readBuffer, tokenSource.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("[-] No response after 3000 ms - legitimation failed");
    return;
}
catch (IOException)
{
    Console.WriteLine("[-] Connection closed by the PLC - legitimation failed");
    return;
}

var legitResponse = new SetVarSubStreamedResponse(readBuffer.AsSpan()[..read]);
if (Enum.IsDefined(legitResponse.StatusCode))
{
    if (legitResponse.StatusCode != EStatusCode.InvalidPassword)
    {
        Helpers.UseColor(() =>
        {
            Console.WriteLine($"[++] Legitimation successful: {Enum.GetName(legitResponse.StatusCode)}. Check Wireshark to be sure"); 
        }, ConsoleColor.Green);   
    }
    else
    {
        Console.WriteLine("[-] Legitimation failed: invalid password (the PLC was happy with the crypto stuff tho)");
    }
}
else
{
    Console.WriteLine($"[-] Legitimation failed: {(int)legitResponse.StatusCode}. Please create an issue on GitHub and include a Wireshark dump.");
}