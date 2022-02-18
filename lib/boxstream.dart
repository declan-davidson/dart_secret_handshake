import 'dart:io';
import 'dart:typed_data';
import 'package:dart_secret_handshake/crypto.dart';
import 'package:dart_secret_handshake/util.dart';

Uint8List buildMessage(Uint8List message, Uint8List secretBoxKey, Uint8List secretBoxNonce){
  Uint8List encryptedMessage, encryptedMessageBodyAuthTag, encryptedMessageBody;
  Uint8List encryptedHeader, encryptedHeaderMessage;
  Uint16List bodyLength = Uint16List(1);

  encryptedMessage = generateSecretBox(secretBoxKey, message, nonce: secretBoxNonce);

  encryptedMessageBodyAuthTag = encryptedMessage.sublist(0, 16);
  encryptedMessageBody = encryptedMessage.sublist(16);

  bodyLength.buffer.asUint16List()[0] = encryptedMessageBody.length;
  encryptedHeaderMessage = toBytes([bodyLength.buffer.asUint8List(), encryptedMessageBodyAuthTag]);
  encryptedHeader = generateSecretBox(secretBoxKey, encryptedHeaderMessage, nonce: secretBoxNonce);

  return toBytes([encryptedHeader, encryptedMessageBody]);
}

List<Uint8List> getReceivedMessageMetadata(Uint8List encryptedHeader, Uint8List secretBoxKey, Uint8List secretBoxNonce) {
  Uint8List header, bodyLength, encryptedMessageBodyAuthTag;

  header = openSecretBox(encryptedHeader, secretBoxKey, secretBoxNonce);

  bodyLength = header.sublist(0, 2);
  encryptedMessageBodyAuthTag = header.sublist(2);

  return [bodyLength, encryptedMessageBodyAuthTag];
}

Uint8List receiveMessage(Uint8List encryptedMessageBody, Uint8List encryptedMessageBodyAuthTag, Uint8List secretBoxKey, Uint8List secretBoxNonce){
  Uint8List reconstructedEncryptedMessage, message;

  reconstructedEncryptedMessage = toBytes([encryptedMessageBodyAuthTag, encryptedMessageBody]);
  message = openSecretBox(reconstructedEncryptedMessage, secretBoxKey, secretBoxNonce);

  return message;
}

Uint8List buildGoodbye(Uint8List secretBoxKey, Uint8List secretBoxNonce){
  Uint8List message = Uint8List.fromList(List<int>.filled(18, 0));

  return generateSecretBox(secretBoxKey, message, nonce: secretBoxNonce);
}

class BoxStream {
  final Uint8List _writerSecretBoxKey;
  Uint8List _writerSecretBoxNonce;
  final Uint8List _readerSecretBoxKey;
  Uint8List _readerSecretBoxNonce;
  final Socket _socket;

  BoxStream(this._writerSecretBoxKey, this._writerSecretBoxNonce, this._readerSecretBoxKey, this._readerSecretBoxNonce, this._socket);

  void send(Uint8List message) {
    List<Uint8List> messageChunks = _splitMessage(message);
    Uint8List secretBoxes = Uint8List.fromList(List.empty());

    for(Uint8List chunk in messageChunks){
      Uint8List headerNonce = cloneUint8List(_writerSecretBoxNonce);
      Uint8List messageNonce = incrementNonce(_writerSecretBoxNonce);

      Uint8List encryptedMessage, encryptedMessageBodyAuthTag, encryptedMessageBody;
      Uint8List encryptedHeader, encryptedHeaderMessage;
      Uint16List bodyLength = Uint16List(1);

      encryptedMessage = generateSecretBox(_writerSecretBoxKey, chunk, nonce: messageNonce);

      encryptedMessageBodyAuthTag = encryptedMessage.sublist(0, 16);
      encryptedMessageBody = encryptedMessage.sublist(16);

      bodyLength.buffer.asUint16List()[0] = encryptedMessageBody.length;
      encryptedHeaderMessage = toBytes([bodyLength.buffer.asUint8List(), encryptedMessageBodyAuthTag]);
      encryptedHeader = generateSecretBox(_writerSecretBoxKey, encryptedHeaderMessage, nonce: headerNonce);

      //_socket.add(toBytes([encryptedHeader, encryptedMessageBody]));
      secretBoxes = toBytes([secretBoxes, encryptedHeader, encryptedMessageBody]);
      incrementNonce(_writerSecretBoxNonce);
    }
    
    _socket.add(secretBoxes);
  }

  List<Uint8List> receieve(Uint8List data){
    List<Uint8List> decryptedMessages = List.empty(growable: true);
    int lastBodyEnd = 0;

    do {
      Uint8List encryptedMessageBody, encryptedHeader, encryptedMessageBodyAuthTag, reconstructedEncryptedMessage, header, message;
      int bodyLength;
      int messageStart = lastBodyEnd;
      int headerEnd = messageStart + 34;
      int bodyEnd = 0;
      
      Uint8List headerNonce = _readerSecretBoxNonce;

      encryptedHeader = data.sublist(messageStart, headerEnd);
      header = openSecretBox(encryptedHeader, _readerSecretBoxKey, headerNonce);
      if(isGoodbye(header)){
        _socket.close();
        return List<Uint8List>.empty();
      }
      bodyLength = header.sublist(0, 2).buffer.asInt16List()[0];
      encryptedMessageBodyAuthTag = header.sublist(2);
      bodyEnd = headerEnd + bodyLength;
      lastBodyEnd = bodyEnd;

      Uint8List messageNonce = incrementNonce(_readerSecretBoxNonce);

      encryptedMessageBody = data.sublist(headerEnd, bodyEnd);
      reconstructedEncryptedMessage = toBytes([encryptedMessageBodyAuthTag, encryptedMessageBody]);
      message = openSecretBox(reconstructedEncryptedMessage, _readerSecretBoxKey, messageNonce);

      decryptedMessages.add(message);
      incrementNonce(_readerSecretBoxNonce);
    } while(lastBodyEnd < data.lengthInBytes);

    //return toBytes(decryptedMessages);
    return decryptedMessages;
  }

  void sendGoodbye(){
    Uint8List message = Uint8List.fromList(List<int>.filled(18, 0));

    _socket.add(generateSecretBox(_writerSecretBoxKey, message, nonce: _writerSecretBoxNonce));
  }

  bool isGoodbye(Uint8List message){
    //We currently have an issue where the message won't equate to the known goodbye message correctly, thus an elementwise comparison needs to be done until a solution is found
    //This may be solvable by using a ListEquality object from the collections library
    if(message.length == 18){
      for(int i = 0; i < message.length; i++){
        if(message[i] != 0) return false;
      }
      return true;
    }
    return false;
  }

  List<Uint8List> _splitMessage(Uint8List message){
    int parts = (message.lengthInBytes / 4096).ceil();
    List<Uint8List> messageChunks = List.empty(growable: true);

    for(int i = 0; i < parts; i++){
      int start = 4096 * i;
      int end =  message.lengthInBytes <  4096 * (i + 1) ? message.lengthInBytes : 4096 * (i + 1);

      messageChunks.add(message.sublist(start, end));
    }

    return messageChunks;
  }

  Uint8List incrementNonce(Uint8List nonce){
    for(int i = nonce.lengthInBytes - 1; i >= 0; i--){
      if(nonce[i] == 255){
        nonce[i] = 0;
      }
      else{
        nonce[i]++;
        break;
      }
    }

    return nonce;
  }

  Uint8List cloneUint8List(Uint8List original){
    Uint8List clone = Uint8List(original.length);

    for(int i = 0; i < original.length; i++){
      clone[i] = original[i];
    }

    return clone;
  }
}

/*
class WriterBoxStream extends BoxStream {
  WriterBoxStream(Uint8List secretBoxKey, Uint8List secretBoxNonce) : super(secretBoxKey, secretBoxNonce);

  Uint8List buildMessage(Uint8List message, Uint8List secretBoxKey, Uint8List secretBoxNonce){
    Uint16List bodyLength = Uint16List(1);
    Uint8List encryptedMessage =  generateSecretBox(secretBoxKey, message, nonce: secretBoxNonce);

    Uint8List encryptedMessageBodyAuthTag = encryptedMessage.sublist(0, 16);
    Uint8List encryptedMessageBody = encryptedMessage.sublist(16);

    bodyLength.buffer.asUint16List()[0] = encryptedMessageBody.length;
    Uint8List encryptedHeaderMessage = toBytes([bodyLength.buffer.asUint8List(), encryptedMessageBodyAuthTag]);
    Uint8List encryptedHeader = generateSecretBox(secretBoxKey, encryptedHeaderMessage, nonce: secretBoxNonce);

    return toBytes([encryptedHeader, encryptedMessageBody]);
  }
}

class ReaderBoxStream extends BoxStream {
  ReaderBoxStream(Uint8List secretBoxKey, Uint8List secretBoxNonce) : super(secretBoxKey, secretBoxNonce);

  Uint8List receiveMessage(Uint8List encryptedMessageBody, Uint8List encryptedMessageBodyAuthTag){
    Uint8List reconstructedMessage = toBytes([encryptedMessageBodyAuthTag, encryptedMessageBody]);
    Uint8List message = openSecretBox(reconstructedMessage, secretBoxKey, secretBoxNonce);

    return message;
  }

  List<Uint8List> getReceivedMessageMetadata(Uint8List encryptedHeader) {
    Uint8List header = openSecretBox(encryptedHeader, secretBoxKey, secretBoxNonce);

    Uint8List bodyLength = header.sublist(0, 2);
    Uint8List encryptedMessageBodyAuthTag = header.sublist(2);

    return [bodyLength, encryptedMessageBodyAuthTag];
  }
}
*/