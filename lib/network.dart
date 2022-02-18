import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_secret_handshake/boxstream.dart';
import 'package:dart_secret_handshake/crypto.dart';
import 'package:libsodium/libsodium.dart';
//import 'package:dart_muxrpc/dart_muxrpc.dart';

class Connection {
  Socket client;
  PeerCrypto crypto;
  BoxStream boxStream;

  Connection(this.client, this.crypto, this.boxStream);
}

abstract class Peer{
  void start();
  //void finish();
  void send(Uint8List message, { int clientNumber });
}

class Client {
  late Socket socket;
  late ClientCrypto crypto;
  late BoxStream boxStream;
  String remoteAddress;
  int remotePort;
  KeyPair longtermKeys;
  Uint8List remotePk;
  StreamSink<Uint8List> sink;

  Client(this.remoteAddress, this.remotePort, this.longtermKeys, this.remotePk, this.sink){
    crypto = ClientCrypto(longtermKeys: longtermKeys, remotePk: remotePk);
  }

  @override
  Future<void> start() async {
    socket = await Socket.connect(InternetAddress.tryParse("192.168.1.64"), 4567);
    Stream<Uint8List> stream = socket.asBroadcastStream();
    /* socket.add(crypto.buildHello());
    print("Sent hello");
    await for(Uint8List serverHello in stream){
      if(crypto.verifyHello(serverHello)){
        verifiedHello = true;
        print("Verified hello!");
        socket.add(crypto.buildAuthenticate());
        print("Sent authenticate");
      }
      break;
    }
    await for(Uint8List serverAuth in stream){
      if(crypto.verifyAuthenticate(serverAuth)){
        verifiedAuth = true;
        print("Verified authenticate!");
        crypto.deriveBoxStreamSecrets();
        boxStream = BoxStream(crypto.writerBoxStreamKey, crypto.writerBoxStreamNonce, crypto.readerBoxStreamKey, crypto.readerBoxStreamNonce, socket);
      }
      break;
    } */
    await performHandshake(stream);

    stream.listen((data) {
      List<Uint8List> messages = boxStream.receieve(data);
      messages.forEach((message) { sink.add(message); });
    },
    onDone: () {
      print("Connection done");
    });
    
    print("Handshake complete");
  }

  Future<void> performHandshake(Stream<Uint8List> stream) async {
    bool verifiedHello = false;

    socket.add(crypto.buildHello());

    await for(Uint8List data in stream){
      if(!verifiedHello){
        if(crypto.verifyHello(data)){
          verifiedHello = true;
          socket.add(crypto.buildAuthenticate());
        }
        else{
          print("Failed to verify hello. Closing socket.");
          socket.close();
        }
      }
      else{
        if(crypto.verifyAuthenticate(data)){
          crypto.deriveBoxStreamSecrets();
          boxStream = BoxStream(crypto.writerBoxStreamKey, crypto.writerBoxStreamNonce, crypto.readerBoxStreamKey, crypto.readerBoxStreamNonce, socket);
          break;
        }
        else{
          print("Failed to verify auth. Closing socket.");
          socket.close();
        }
      }
    }
  }

/*   void onData(Uint8List data) async {
    if(!verifiedHello){
      if(crypto.verifyHello(data)){
        verifiedHello = true;
        print("Verified hello!");
        socket.add(crypto.buildAuthenticate());
        print("Sent authenticate");
      }
    }
    else if(!verifiedAuth){
      if(crypto.verifyAuthenticate(data)){
        verifiedAuth = true;
        print("Verified authenticate!");
        crypto.deriveBoxStreamSecrets();
        boxStream = BoxStream(crypto.writerBoxStreamKey, crypto.writerBoxStreamNonce, crypto.readerBoxStreamKey, crypto.readerBoxStreamNonce, socket);       
      }
    }
    else{
      Uint8List message = boxStream.receiveMessage(data);
      print(message.length);
    }
  } */

  void send(Uint8List message) {
    boxStream.send(message);
  }

  void finish(){
    boxStream.sendGoodbye();
    socket.close();
  }

  void checkBoxStream(){
    print("Is boxStream null? " + (boxStream == null ? "yes" : "no"));
  }
}

class Server {
  int clientCounter = 1;
  Map<int, BoxStream> boxStreams = {};
  late ServerSocket socket;
  StreamSink<ClientMessageTuple> sink;
  KeyPair longtermKeys;

  Server(this.longtermKeys, this.sink);

  void start() async {
    socket = await ServerSocket.bind(InternetAddress.tryParse("192.168.1.64"), 4567);
    socket.listen(onConnection);
  }

  void send(int clientNumber, Uint8List message){
    BoxStream? boxStream = boxStreams[clientNumber];

    if(boxStream != null){
      boxStream.send(message);
    }
  }

  void onConnection(Socket client) async {
    int clientNumber = clientCounter++;
    ServerCrypto crypto = ServerCrypto(longtermKeys: longtermKeys);
    late BoxStream boxStream;
    bool verifiedHello = false, verifiedAuth = false;

    //We won't include onDone here, as we'll use the goodbye message to detect client closure instead
    client.listen((data) {
      if(!verifiedHello){
        if(crypto.verifyHello(data)){
          verifiedHello = true;
          print("Verified hello!");
          client.add(crypto.buildHello());
          print("Sent hello");
        }
      }
      else if(!verifiedAuth){
        if(crypto.verifyAuthenticate(data)){
          verifiedAuth = true;
          print("Verified authenticate!");
          client.add(crypto.buildAuthenticate());
          print("Sent authenticate");
          crypto.deriveBoxStreamSecrets();
          boxStream = BoxStream(crypto.writerBoxStreamKey, crypto.writerBoxStreamNonce, crypto.readerBoxStreamKey, crypto.readerBoxStreamNonce, client);
          boxStreams[clientNumber] = boxStream;
          print("Active clients: ");
          boxStreams.forEach((key, value) {print(key);});
        }
      }
      else{
        List<Uint8List> messages = boxStream.receieve(data);
        
        for(Uint8List message in messages){
          sink.add(ClientMessageTuple(clientNumber, message));
        }
      }
     },
     onError: (error) { handleError(error, client); },
     onDone: () { 
       print("That connection is done");
       handleDone(clientNumber);
       });
  }

  void handleDone(int clientNumber){
    boxStreams.remove(clientNumber);
  }

  void handleError(SocketException error, Socket client){
    print(error.message);
    print(error.osError);
    client.close();
  }

  Future<void> reply(BoxStream boxStream) async{
    await Future.delayed(const Duration(seconds: 2));
    boxStream.send(Uint8List.fromList("Reply".codeUnits));
    return;
  }
}

class ClientMessageTuple{
  int clientNumber;
  Uint8List message;

  ClientMessageTuple(this.clientNumber, this.message);
}

abstract class MessageProcessor{
  void process(Socket peer, Uint8List encodedMessage);
  }