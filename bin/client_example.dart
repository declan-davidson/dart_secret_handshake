import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'package:dart_secret_handshake/crypto.dart';
import 'package:dart_secret_handshake/util.dart';
import 'package:dart_secret_handshake/network.dart';
import 'package:libsodium/libsodium.dart';
import 'package:dart_secret_handshake/boxstream.dart';
import 'package:dart_muxrpc/dart_muxrpc.dart';

void main(List<String> arguments) async {
  print("Starting client");
  Client client = Client("127.0.0.1", 4567, Sodium.cryptoSignSeedKeypair(defaultClientSeed), defaultServerLongtermKeys.pk);

  await client.start();

  RpcMessage request1 = rpcRequest("blobs.has", ["&WWw4tQJ6ZrM7o3gA8lOEAcO4zmyqXqb/3bmIKTLQepo=.sha256"], "async", 1);
  RpcMessage request2 = rpcRequest("createHistoryStream", [{"id": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519"}], "source", 2);

  client.send(encodeRpcMessage(request1));
  //await Future.delayed(const Duration(seconds: 1), (){});
  client.send(encodeRpcMessage(request2));
  await Future.delayed(const Duration(seconds: 8));
  client.finish();

  //await Future.delayed(const Duration(seconds: 2), (){});
  //print("still running");

  /* print("Send call 3");
  await client.send(Uint8List.fromList((List<int>.filled(5000, 2)))); */
}
