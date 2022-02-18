import 'dart:typed_data';
import 'dart:convert';
import 'package:libsodium/libsodium.dart';

Uint8List defaultNetworkId = base64Decode("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=");
Uint8List zeroNonce = Uint8List.fromList(List<int>.filled(24, 0));
Uint8List defaultServerSeed = Uint8List.fromList(List.filled(32, 0));
Uint8List defaultClientSeed = Uint8List.fromList(List.filled(32, 1));
Uint8List defaultServerEphemeralSeed = Uint8List.fromList(List.filled(32, 3));
Uint8List defaultClientEphemeralSeed = Uint8List.fromList(List.filled(32, 4));
KeyPair defaultServerLongtermKeys = Sodium.cryptoSignSeedKeypair(defaultServerSeed);
KeyPair defaultClientLongtermKeys = Sodium.cryptoSignSeedKeypair(defaultClientSeed);
Uint8List goodbyeMessage = Uint8List.fromList(List<int>.filled(18, 0));

List<Uint8List> splitMessage(Uint8List message){
  print("in splitmessage");
  int parts = (message.lengthInBytes / 4096).ceil();
  List<Uint8List> messageChunks = List.empty(growable: true);

  for(int i = 0; i < parts; i++){
    int start = 4096 * i;
    int end =  message.lengthInBytes <  4096 * (i + 1) ? message.lengthInBytes : 4096 * (i + 1);

    messageChunks.add(message.sublist(start, end));
  }

  return messageChunks;
}

Uint8List toBytes(List<Uint8List> elements){
  BytesBuilder bb = BytesBuilder();

  for(Uint8List element in elements){
    bb.add(element);
  }

  Uint8List bytes = bb.toBytes();
  bb.clear(); //This may be unnecessary
  return bytes;
}