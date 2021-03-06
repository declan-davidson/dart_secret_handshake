import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'package:dart_secret_handshake/crypto.dart';
import 'package:dart_secret_handshake/util.dart';
import 'package:dart_secret_handshake/network.dart';
import 'package:libsodium/libsodium.dart';
import 'package:dart_secret_handshake/boxstream.dart';

void main(List<String> arguments) async {
  print("start");
  Server server = Server(Sodium.cryptoSignSeedKeypair(defaultServerSeed));
  Client client = Client("127.0.0.1", 4567, Sodium.cryptoSignSeedKeypair(defaultClientSeed), defaultServerLongtermKeys.pk);

  server.start();
  await client.start();

  print("Start of send block");
  client.send(Uint8List.fromList((List<int>.filled(7000, 0))));
  client.send(Uint8List.fromList((List<int>.filled(800, 1))));
  client.send(Uint8List.fromList((List<int>.filled(2000, 2))));
}
