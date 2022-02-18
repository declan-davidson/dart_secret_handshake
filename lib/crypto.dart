import 'dart:typed_data';
import 'package:libsodium/libsodium.dart';
import 'util.dart';
import 'package:crypto/crypto.dart' show sha256;

Uint8List generateSecretBox(Uint8List secretBoxKey, Uint8List secretBoxMessage, { Uint8List? additionalSecretBoxMessageElement, Uint8List? nonce }){
  Uint8List finalSecretBoxMessage;
  additionalSecretBoxMessageElement != null ? finalSecretBoxMessage = toBytes([secretBoxMessage, additionalSecretBoxMessageElement]) : finalSecretBoxMessage = secretBoxMessage;

  return Sodium.cryptoSecretboxEasy(finalSecretBoxMessage, (nonce != null ? nonce : zeroNonce), secretBoxKey);
}

Uint8List generateHash(List<Uint8List> elements){
  List<int> hashMaterial = toBytes(elements).toList();
  return Uint8List.fromList(sha256.convert(hashMaterial).bytes);
}

Uint8List openSecretBox(Uint8List secretBox, Uint8List secretBoxKey, Uint8List secretBoxNonce){
  return Sodium.cryptoSecretboxOpenEasy(secretBox, secretBoxNonce, secretBoxKey);
}

abstract class PeerCrypto {
  KeyPair longtermKeys;
  late KeyPair ephemeralKeys;
  late Uint8List remotePk;
  late Uint8List remoteEphemeralPk;
  Uint8List networkId = defaultNetworkId;
  late Uint8List writerBoxStreamKey;
  late Uint8List writerBoxStreamNonce;
  late Uint8List readerBoxStreamKey;
  late Uint8List readerBoxStreamNonce;
  late Uint8List detachedSignatureA;
  late Uint8List sharedSecret_ab;
  late Uint8List sharedSecret_aB;
  late Uint8List sharedSecret_Ab;
  late Uint8List hashedSharedSecret_ab;

  PeerCrypto({ required this.longtermKeys, Uint8List? remotePk, Uint8List? networkId, KeyPair? ephemeralKeys }){
    if(remotePk != null) this.remotePk = remotePk;
    if(networkId != null) this.networkId = networkId; 
    ephemeralKeys != null ? this.ephemeralKeys = ephemeralKeys : this.ephemeralKeys = Sodium.cryptoBoxSeedKeypair(RandomBytes.buffer(32));  
  }

  Uint8List buildHello() {
    Uint8List hmac = Sodium.cryptoAuth(ephemeralKeys.pk, networkId);

    return toBytes([hmac, ephemeralKeys.pk]);
  }

  bool verifyHello(Uint8List response){
    bool verified;

    if(response.lengthInBytes != 64) return false;

    Uint8List receivedHmac = response.sublist(0, 32);
    remoteEphemeralPk = response.sublist(32, 64);
    
    verified = Sodium.cryptoAuthVerify(receivedHmac, remoteEphemeralPk, networkId);

    if(verified){
      deriveSharedSecret_ab();
      deriveSharedSecret_aB();
    }

    return verified;
  }

  Uint8List buildAuthenticate();

  bool verifyAuthenticate(Uint8List secretBox);

  bool verifyAuthenticationBase(Uint8List secretBox, List<Uint8List> keyElements, List<Uint8List> expectedDetachedSignatureMessageElements){
    Uint8List secretBoxKey, secretBoxContents, expectedDetachedSignatureMessage;
    Uint8List? detachedSignature;

    secretBoxKey = generateHash(keyElements);
    secretBoxContents = Sodium.cryptoSecretboxOpenEasy(secretBox, zeroNonce, secretBoxKey);

    if(secretBoxContents.lengthInBytes == 96){
      detachedSignature = secretBoxContents.sublist(0, 64);
      detachedSignatureA = detachedSignature;
      remotePk = secretBoxContents.sublist(64, 96);
    }
    else{
      detachedSignature = secretBoxContents;
    }

    expectedDetachedSignatureMessage = toBytes(expectedDetachedSignatureMessageElements);
    return Sodium.cryptoSignVerifyDetached(detachedSignature, expectedDetachedSignatureMessage, remotePk) == 0;
  }

  Uint8List deriveSharedSecret({ required Uint8List publicKey, required Uint8List secretKey }){
    return Sodium.cryptoScalarmult(secretKey, publicKey);
  }

  void deriveSharedSecret_ab(){
    sharedSecret_ab = deriveSharedSecret(publicKey: remoteEphemeralPk, secretKey: ephemeralKeys.sk);
    hashedSharedSecret_ab = generateHash([sharedSecret_ab]);
  }

  void deriveSharedSecret_aB();

  void deriveSharedSecret_Ab();

  Uint8List generateDetachedSignature(List<Uint8List> messageElements){
    Uint8List detachedSignatureMessage;
    
    detachedSignatureMessage = toBytes(messageElements);
    return Sodium.cryptoSignDetached(detachedSignatureMessage, longtermKeys.sk);
  }

  void deriveBoxStreamSecrets(){
    Uint8List doubleHashedSecretBoxKeyBase = generateHash([generateHash([networkId, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab])]);

    //WRITER
    writerBoxStreamKey = generateHash([doubleHashedSecretBoxKeyBase, remotePk]);
    writerBoxStreamNonce = Sodium.cryptoAuth(remoteEphemeralPk, networkId).sublist(0, 24);

    //READER
    readerBoxStreamKey = generateHash([doubleHashedSecretBoxKeyBase, longtermKeys.pk]);
    readerBoxStreamNonce = Sodium.cryptoAuth(ephemeralKeys.pk, networkId).sublist(0, 24);
  }
}

class ClientCrypto extends PeerCrypto {
  ClientCrypto({ required KeyPair longtermKeys, required Uint8List remotePk, Uint8List? networkId, KeyPair? ephemeralKeys }) : 
    super(longtermKeys: longtermKeys, remotePk: remotePk, networkId: networkId, ephemeralKeys: ephemeralKeys);
  
  @override
  Uint8List buildAuthenticate(){
    detachedSignatureA = generateDetachedSignature([networkId, remotePk, hashedSharedSecret_ab]);

    return generateSecretBox(generateHash([networkId, sharedSecret_ab, sharedSecret_aB]), detachedSignatureA, additionalSecretBoxMessageElement: longtermKeys.pk);
  }

  @override
  bool verifyAuthenticate(Uint8List secretBox){
    deriveSharedSecret_Ab();

    return verifyAuthenticationBase(secretBox, [networkId, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab], [networkId, detachedSignatureA, longtermKeys.pk, hashedSharedSecret_ab]);
  }

  @override
  void deriveSharedSecret_aB(){
    sharedSecret_aB = deriveSharedSecret(publicKey: Sodium.cryptoSignEd25519PkToCurve25519(remotePk), secretKey: ephemeralKeys.sk);
  }

  @override
  void deriveSharedSecret_Ab() {
    sharedSecret_Ab = deriveSharedSecret(publicKey: remoteEphemeralPk, secretKey: Sodium.cryptoSignEd25519SkToCurve25519(longtermKeys.sk));
  }
}

class ServerCrypto extends PeerCrypto {
  ServerCrypto({ required KeyPair longtermKeys, Uint8List? networkId, KeyPair? ephemeralKeys }) :
    super(longtermKeys: longtermKeys, networkId: networkId, ephemeralKeys: ephemeralKeys);

  @override
  Uint8List buildAuthenticate(){
    Uint8List detachedSignatureB = generateDetachedSignature([networkId, detachedSignatureA, remotePk, hashedSharedSecret_ab]);
    
    return generateSecretBox(generateHash([networkId, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]), detachedSignatureB);
  }

  @override
  bool verifyAuthenticate(Uint8List secretBox){
    bool verified = verifyAuthenticationBase(secretBox, [networkId, sharedSecret_ab, sharedSecret_aB], [networkId, longtermKeys.pk, hashedSharedSecret_ab]);
    if(verified) deriveSharedSecret_Ab();

    return verified;
  }

  @override
  void deriveSharedSecret_aB(){
    sharedSecret_aB = deriveSharedSecret(publicKey: remoteEphemeralPk, secretKey: Sodium.cryptoSignEd25519SkToCurve25519(longtermKeys.sk));
  }

   @override
  void deriveSharedSecret_Ab() {
    sharedSecret_Ab = deriveSharedSecret(publicKey: Sodium.cryptoSignEd25519PkToCurve25519(remotePk), secretKey: ephemeralKeys.sk);
  }
}