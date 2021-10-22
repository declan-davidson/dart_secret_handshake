import 'dart:typed_data';
import 'dart:convert';

Uint8List defaultNetworkId = base64Decode("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=");
Uint8List zeroNonce = Uint8List.fromList(List<int>.filled(24, 0));
Uint8List defaultServerSeed = Uint8List.fromList(List.filled(32, 0));
Uint8List defaultClientSeed = Uint8List.fromList(List.filled(32, 1));
Uint8List defaultServerEphemeralSeed = Uint8List.fromList(List.filled(32, 3));
Uint8List defaultClientEphemeralSeed = Uint8List.fromList(List.filled(32, 4));