import 'dart:typed_data';
import 'package:libsodium/libsodium.dart';
import 'util.dart';
import 'package:crypto/crypto.dart' show sha256;

abstract class Peer {
  KeyPair longtermKeys;
  late KeyPair ephemeralKeys;
  late Uint8List remotePk;
  late Uint8List remoteEphemeralPk;
  Uint8List networkId = defaultNetworkId;
  late Uint8List detachedSignatureA;
  late Uint8List sharedSecret_ab;
  late Uint8List sharedSecret_aB;
  late Uint8List sharedSecret_Ab;
  late Uint8List hashedSharedSecret_ab;

  Peer({ required this.longtermKeys, Uint8List? remotePk, Uint8List? networkId, KeyPair? ephemeralKeys }){
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

  Uint8List deriveSharedSecret({ required Uint8List publicKey, required Uint8List secretKey }){
    return Sodium.cryptoScalarmult(secretKey, publicKey);
  }

  void deriveSharedSecret_ab(){
    sharedSecret_ab = deriveSharedSecret(publicKey: remoteEphemeralPk, secretKey: ephemeralKeys.sk);
    hashedSharedSecret_ab = Uint8List.fromList(sha256.convert(sharedSecret_ab.toList()).bytes);
  }

  void deriveSharedSecret_aB();

  void deriveSharedSecret_Ab();

  Uint8List toBytes(List<Uint8List> elements){
    BytesBuilder bb = BytesBuilder();

    for(Uint8List element in elements){
      bb.add(element);
    }

    Uint8List bytes = bb.toBytes();
    bb.clear(); //This may be unnecessary
    return bytes;
  }

  Uint8List generateDetachedSignature(List<Uint8List> messageElements){
    Uint8List detachedSignatureMessage;
    
    detachedSignatureMessage = toBytes(messageElements);
    return Sodium.cryptoSignDetached(detachedSignatureMessage, longtermKeys.sk);
  }

  Uint8List generateSecretBox(List<Uint8List> keyElements, Uint8List detachedSignature, [ Uint8List? additionalSecretBoxMessageElement ]){
    Uint8List secretBoxKey, secretBoxMessage;

    secretBoxKey = generateSecretBoxKey(keyElements);
    additionalSecretBoxMessageElement != null ? secretBoxMessage = toBytes([detachedSignature, additionalSecretBoxMessageElement]) : secretBoxMessage = detachedSignature;
    return Sodium.cryptoSecretboxEasy(secretBoxMessage, zeroNonce, secretBoxKey);
  }

  Uint8List generateSecretBoxKey(List<Uint8List> keyElements){
    Uint8List secretBoxKeyMaterial = toBytes(keyElements);
    return Uint8List.fromList(sha256.convert(secretBoxKeyMaterial.toList()).bytes);
  }

  bool verifyAuthenticationBase(Uint8List secretBox, List<Uint8List> keyElements, List<Uint8List> expectedDetachedSignatureMessageElements){
    Uint8List secretBoxKey, secretBoxContents, expectedDetachedSignatureMessage;
    Uint8List? detachedSignature;

    secretBoxKey = generateSecretBoxKey(keyElements);
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
}

class Client extends Peer {
  Client({ required KeyPair longtermKeys, required Uint8List remotePk, Uint8List? networkId, KeyPair? ephemeralKeys }) : 
    super(longtermKeys: longtermKeys, remotePk: remotePk, networkId: networkId, ephemeralKeys: ephemeralKeys);
  
  @override
  Uint8List buildAuthenticate(){
    detachedSignatureA = generateDetachedSignature([networkId, remotePk, hashedSharedSecret_ab]);

    return generateSecretBox([networkId, sharedSecret_ab, sharedSecret_aB], detachedSignatureA, longtermKeys.pk);
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

class Server extends Peer {
  Server({ required KeyPair longtermKeys, Uint8List? networkId, KeyPair? ephemeralKeys }) :
    super(longtermKeys: longtermKeys, networkId: networkId, ephemeralKeys: ephemeralKeys);

  @override
  Uint8List buildAuthenticate(){
    Uint8List detachedSignatureB = generateDetachedSignature([networkId, detachedSignatureA, remotePk, hashedSharedSecret_ab]);
    
    return generateSecretBox([networkId, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab], detachedSignatureB);
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