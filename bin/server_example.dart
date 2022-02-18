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
  print("Starting server");
  Server server = Server(Sodium.cryptoSignSeedKeypair(defaultServerSeed));
  server.start();
}
