using System.Net;
using System.Net.Sockets;
using HarpoS7;
using HarpoS7.Auth;
using HarpoS7.Extensions;
using HarpoS7.Packets;
using HarpoS7.PoC;
using HarpoS7.PoC.Models;
using HarpoS7.PublicKeys.Exceptions;
using HarpoS7.PublicKeys.Impl;
using HarpoS7.Transport;
using HarpoS7.Utilities.Auth;
using HarpoS7.Utilities.Extensions;

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
await using var stream = new CotpStream(client.GetStream());

// Send COTP Connection Request and wait for Connection Confirm
Console.WriteLine("Sending COTP CR...");
await stream.WriteConnectionRequestAsync("SIMATIC-ROOT-HMI");

Console.WriteLine("Waiting for COTP Connection Confirm");
await stream.ReadConnectionConfirmAsync();

// Write empty DT-Data
await stream.WriteEmptyDtDataAsync();

// Send S7CommPlus CreateObject request (creates a session object on the PLC)
var createObjectPacket = CreateObjectRequest.Serialize();

Console.WriteLine("Creating a session object");
await stream.WriteAsync(createObjectPacket);

Console.WriteLine("Waiting for create object response");
var read = await stream.ReadAsync(readBuffer);

await stream.WriteEmptyDtDataAsync();

// Parse the CreateObject response to extract session ID, fingerprint, and challenge
CreateObjectResponse createObjectResponse;
try
{
    createObjectResponse = new CreateObjectResponse(readBuffer.AsSpan(0, read));
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"[-] {ex.Message}");
    return;
}

var sessionId = createObjectResponse.SessionId;
var fingerprintString = createObjectResponse.Fingerprint;
var challenge = createObjectResponse.Challenge;

Console.WriteLine($"Session ID: 0x{sessionId:X8}");
Console.Write("Challenge: ");
Helpers.PrintBuffer(challenge);

Console.WriteLine($"Reversed fingerprint: {fingerprintString}");

// Reverse string and parse fingerprint
var publicKeyFingerprint = new byte[Constants.KeyIdLength];
Helpers.ParseAndReverseBytes(fingerprintString, publicKeyFingerprint);

Console.Write("Actual fingerprint: ");
Helpers.PrintBuffer(publicKeyFingerprint);

// get the matching public key from the KeyStore
var store = new DefaultPublicKeyStore();
var publicKey = new byte[store.GetPublicKeyLength(fingerprintString)];

try
{
    store.ReadPublicKey(publicKey.AsSpan(), fingerprintString);
}
catch (UnknownPublicKeyException)
{
    Console.WriteLine("[-] Public key for this fingerprint was not found in the key store. " +
                      "You need to find the appropriate key and add it to the key store.");
    return;
}

Console.WriteLine("[+] Public key found");

// create buffers
var sessionKey = new byte[Constants.SessionKeyLength];
var keyBlob = new byte[fingerprintString.StartsWith("03:") ? CommonConstants.EncryptedBlobLengthPlcSim : CommonConstants.EncryptedBlobLengthRealPlc];

Console.WriteLine("Doing the encryption...");

var publicKeyFamily = fingerprintString.ToPublicKeyFamily();

// auth locally
LegacyAuthenticationScheme.Authenticate(
    keyBlob.AsSpan(),
    sessionKey.AsSpan(),
    challenge.AsSpan(),
    publicKey.AsSpan(),
    publicKeyFamily
);

// construct metadata
var pubKeyId = new byte[Constants.KeyIdLength];
var sessionKeyId = new byte[Constants.KeyIdLength];

publicKey.DeriveKeyId(pubKeyId);
sessionKey.DeriveKeyId(sessionKeyId);

// Build the SetMultiVars request packet using the serializer
var setMultiVarsPacket = HarpoS7.Packets.SetMultiVarsRequest.Serialize(
    sessionId,
    pubKeyId,
    sessionKeyId,
    keyBlob.AsSpan(),
    publicKeyFamily
);

// send request
Console.WriteLine("Sending a set multi vars request");
await stream.WriteAsync(setMultiVarsPacket);

var tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for a set var response...");

try
{
	read = await stream.ReadAsync(readBuffer, tokenSource.Token);
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

// Build and send GetVarSubStreamed request using the serializer
Console.WriteLine("Requesting the legitimation challenge");
var getVarSubStreamedPacket = HarpoS7.Packets.GetVarSubStreamedRequest.Serialize(
    sessionKey.AsSpan(), sessionId);
await stream.WriteAsync(getVarSubStreamedPacket);

tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for the challenge...");

try
{
    read = await stream.ReadAsync(readBuffer, tokenSource.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("[-] No response after 3000 ms - legitimation failed");
    return;
}

const int realPlcLegitimationChallengeOffset = 0x34;
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

// Build and send SetVarSubStreamed request using the serializer
var setVarSubStreamedPacket = HarpoS7.Packets.SetVarSubStreamedRequest.Serialize(
    sessionKey.AsSpan(), legitBlob.AsSpan(), sessionId);
await stream.WriteAsync(setVarSubStreamedPacket);

await stream.WriteEmptyDtDataAsync();

tokenSource = new CancellationTokenSource();
tokenSource.CancelAfter(3000);
Console.WriteLine("Waiting for the response...");

try
{
    read = await stream.ReadAsync(readBuffer, tokenSource.Token);
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

var legitResponse = new HarpoS7.Packets.SetVarSubStreamedResponse(readBuffer.AsSpan()[..read]);
var statusCode = (EStatusCode)legitResponse.StatusCode;
if (Enum.IsDefined(statusCode))
{
    if (statusCode != EStatusCode.InvalidPassword)
    {
        Helpers.UseColor(() =>
        {
            Console.WriteLine($"[++] Legitimation successful: {Enum.GetName(statusCode)}. Check Wireshark to be sure"); 
        }, ConsoleColor.Green);   
    }
    else
    {
        Console.WriteLine("[-] Legitimation failed: invalid password (the PLC was happy with the crypto stuff tho)");
    }
}
else
{
    Console.WriteLine($"[-] Legitimation failed: {legitResponse.StatusCode}. Please create an issue on GitHub and include a Wireshark dump.");
}