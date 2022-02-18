import 'package:test/test.dart';
import 'package:dart_secret_handshake/crypto.dart';
import 'package:dart_secret_handshake/util.dart';
import 'package:libsodium/libsodium.dart';
import 'dart:typed_data';

void main() {
  Sodium.init();

  late ServerCrypto server;
  late ClientCrypto client;
  KeyPair serverLongtermKeys = Sodium.cryptoSignSeedKeypair(defaultServerSeed);
  KeyPair serverEphemeralKeys = Sodium.cryptoBoxSeedKeypair(defaultServerEphemeralSeed);
  KeyPair clientLongtermKeys = Sodium.cryptoSignSeedKeypair(defaultClientSeed);
  KeyPair clientEphemeralKeys = Sodium.cryptoBoxSeedKeypair(defaultClientEphemeralSeed);

  setUp(() {
    server = ServerCrypto(longtermKeys: serverLongtermKeys, ephemeralKeys: serverEphemeralKeys);
    client = ClientCrypto(longtermKeys: clientLongtermKeys, remotePk: serverLongtermKeys.pk, ephemeralKeys: clientEphemeralKeys);
  });

  group("Server:", () {
    test("longterm key pair matches expected key pair given default seed", () {
      expect(server.longtermKeys, equals(serverLongtermKeys));
    });

    test("ephemeral key pair matches expected key pair given default seed", () { 
      expect(server.ephemeralKeys, equals(serverEphemeralKeys));
    });

    test("network ID matches default ID", () { 
      expect(server.networkId, equals(defaultNetworkId));
    });
  });

  group("Client:", () {
    test("longterm key pair matches expected key pair given default seed", () {
      expect(client.longtermKeys, equals(clientLongtermKeys));
    });

    test("ephemeral key pair matches expected key pair given default seed", () { 
      expect(client.ephemeralKeys, equals(clientEphemeralKeys));
    });

    test("remote longterm public key matches expected key given default seed", () { 
      expect(client.remotePk, equals(serverLongtermKeys.pk));
    });

    test("network ID matches default ID", () { 
      expect(client.networkId, equals(defaultNetworkId));
    });
  });

  group("Handshake:", () {
    test("client hello is successfully verified", () {
      Uint8List clientHello = client.buildHello();
      bool clientHelloVerified = server.verifyHello(clientHello);

      expect(clientHelloVerified, equals(true));
    });

    test("server hello is successfully verified", () {
      Uint8List clientHello = client.buildHello();
      server.verifyHello(clientHello);
      Uint8List serverHello = server.buildHello();
      bool serverHelloVerified = client.verifyHello(serverHello);

      expect(serverHelloVerified, equals(true));
    });

    test("client authenticate is successfully verified", () {
      Uint8List clientHello = client.buildHello();
      server.verifyHello(clientHello);
      Uint8List serverHello = server.buildHello();
      client.verifyHello(serverHello);
      Uint8List clientAuthenticate = client.buildAuthenticate();
      bool clientAuthenticateVerified = server.verifyAuthenticate(clientAuthenticate);

      expect(clientAuthenticateVerified, equals(true));
    });

    test("server authenticate is successfully verified", () {
      Uint8List clientHello = client.buildHello();
      server.verifyHello(clientHello);
      Uint8List serverHello = server.buildHello();
      client.verifyHello(serverHello);
      Uint8List clientAuthenticate = client.buildAuthenticate();
      server.verifyAuthenticate(clientAuthenticate);
      Uint8List serverAuthenticate = server.buildAuthenticate();
      bool serverAuthenticateVerified = client.verifyAuthenticate(serverAuthenticate);

      expect(serverAuthenticateVerified, equals(true));
    });
  });
}