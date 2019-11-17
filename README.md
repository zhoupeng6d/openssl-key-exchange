# openssl-key-exchange
![MIT](https://img.shields.io/badge/license-MIT-blue.svg)

English | [中文](./README_CN.md)

## About
This project introduces a process and method for key exchange through the ECDH (Elliptic-Curve Diffie–Hellman) algorithm, which can perform AES key negotiation in an insecure communication scenario. Even if a third party listens to all the key exchange information, the final calculated AES key cannot be known, which is to prevent MITM (Man-in-the-middle attack).

This mechanism can be applied to the key negotiation between Bluetooth BLE Peripheral and Central. However, this article focuses more on the key exchange process and principle, rather than the specific application scenario, so it is only abstracted into Client and Server.

The client and the server communicate through [rpclib](https://github.com/rpclib/rpclib), and the server provides some services that can be accessed remotely by the client.

A server provides at least two services, one is a key exchange service and the other is an encrypted data communication service. In this project, our Server binds two services via rpclib:
1. "key_exchange_request", the client accesses that service to complete the key exchange.
2. "encrypted_request", the client accesses that service using the encrypted data after the key exchange is completed.

Messages transmitted between Server and Client use protobuf, protocol definition reference to :[key_exchange.proto](./protos/key_exchange.proto)

## Build & Run
Currently verified on Ubuntu and MacOS, the host needs to install the openssl library and the protobuf3.0+ library.

Install libssl-dev
```shell
$ sudo apt-get install libssl-dev
```

Install protobuf-3.7.0 please refer to [https://github.com/protocolbuffers/protobuf/blob/master/src/README.md](https://github.com/protocolbuffers/protobuf/blob/master/src/README.md)

After installing libssl and protobuf:
```shell
$ git clone https://github.com/zhoupeng6d/openssl-key-exchange.git
$ cd openssl-key-exchange
$ git submodule init
$ git submodule update
$ mkdir build
$ cmake ..
$ make
$ ./server
$ ./client # run the client in another terminal window
```

## File structure
```C++
.
├── CMakeLists.txt                  // CMake build script
├── LICENSE                         // Open source license
├── README.md                       // Project instruction
├── README_CN.md                    // Chinese-simplified instruction
├── README_EN.md                    // English instruction
├── deps                            // Dependent third party library
├── protos
│   └── key_exchange.proto          // Protobuf definition
├── readme_images
└── src
    ├── client.cc                   // Client main code
    ├── common.h                    // Common functions header
    ├── crypto.cc                   // Functions based on the openssl
    ├── crypto.h
    ├── hex_dump.h                  // Print data in hexadecimal
    └── server.cc                   // Server main code
```

## The algorithm standard used in the project:
1. ECDH (Elliptic-Curve Diffie–Hellman NIST P-256)
2. HKDF (HMAC-based Extract-and-Expand Key Derivation Function  Refer to RFC 5869)
3. HMAC (Hash-based Message Authentication Code SHA-256)
4. AES  (AES-256-GCM)

## Flow chart
<div align=center><img width=600 src="./readme_images/flowchart.png"/></div>

**That process consists of two main phases**
1. Key Exchange phase, perform the key exchange, and finally negotiate an AES symmetric key;
2. Encrypted Communication phase，AES encrypted communication using the key negotiated in the previous step.

### Phase I Key Exchange
1. KEY_EXCHANGE_INITIATE Request, client sends its own ECDH public key (65 bytes) and Salt (32 bytes random number) to the Server;
2. KEY_EXCHANGE_INITIATE Response, server sends its own ECDH public key (65 bytes) and Salt (32 bytes random number) to the Client;
3. Key Calculation, After receiving the message sent by the server in the previous step, the client uses the key_calculate() function to calculate the AES key (32 bytes).
4. KEY_EXCHANGE_FINALIZE Request, when the client correctly calculates the AES key, send the message to inform the server to complete the key exchange;
5. Key Calculation, after receiving the message sent by the client in the previous step, the server also performs the key_calculate() function to calculate the AES key;
6. KEY_EXCHANGE_FINALIZE Response, after the key calculation on the server side is completed, reply OK to the client. At this point, the entire key exchange process is complete.

#### The flow of key_calculate()
1. XOR the own Salt and the other's Salt to generate a XorSalt (32 bytes);
2. Using the ECDH public key + private key and the other's ECDH public key, input the ECDH algorithm to calculate a ECDH SharedKey(32 bytes);
3. Use the XorSalt of the first step and the SharedKey of the second step, and use the fixed string "ENCRYPTION" as the Info input to calculate the final AES key using the HKDF algorithm.


### Phase II Encrypted Communication
1. Token generation. Each communication generates a 3-byte random number. Using this random number and its own ECDH public key to calculate a hash value using HMAC, which we call a Token;
2. Insert the random number and Token of the previous step into the Encrypted Request, and send the encrypted Ciphertext to the Server;
3. After receiving the Encrypted Request, the server calculates a Token based on the public key exchanged by the saved key and the random number sent by the client. If the Token is the same as the Token sent by the Client, the device considers the device to be a trusted device. And decrypt the next Ciphertext.

## Device legality verification (this project is not implemented)
If you understand the key exchange process above, then you must have discovered that any client can communicate with the Server using the same set of mechanisms. Obviously our goal is not to implement a [concealed security algorithm](http ://www.ituring.com.cn/book/miniarticle/129179).

To verify the legality of the device, the public key of both parties must be entered into the other device in advance, or the public key can be entered into an authentication server that both parties can access. Information that needs to be entered in advance can be achieved by computing the hash of the device's public key.

According to the above flow chart, we can add the public key verification process after step 1 (Server receives Client's KEY_EXCHANGE_INITIATE Request) and Step 2 (Client receives Server's KEY_EXCHANGE_INITIATE Response), so that Client and Server can mutually authenticate each other. If the identity of the other party does not match the reservation information, then reject its key exchange request.

## Apply to the Bluetooth pairing process
If the mechanism is to be applied between the Bluetooth master and slave devices, the Bluetooth slave device generally provides the corresponding service for the host to access, then the Bluetooth slave device acts as the server role, and the Bluetooth master device acts as the client role.

The slave device provides at least two Service UUIDs, one for the key exchange service and the other for the data encryption communication.

In order to implement Request and Response, each Service UUID implements at least two channels, one for receiving Request (write attribute) and one for sending Response (notify attribute). A typical profile example is as follows:
```
├──UUID 0xFF10        // Primary Service -- Key Exchange
│  ├── UUID 0xFFF1    // Write Characteristic
│  └── UUID 0xFFF2    // Notify Characteristic
│
└──UUID 0xFF20        // Primary Service -- Encrypted Communication
   ├── UUID 0xFFF1    // Write Characteristic
   └── UUID 0xFFF2    // Notify Characteristic
```
In this project, after passing KeyExchange, the Client will add a Token to each EncryptedRequest to identify itself. However, if it is a Bluetooth device, the Token is generated by the slave device (Server), and the Token can be placed in the manufacturer field of the slave's broadcast data, so that it is possible to determine whether the device has undergone key exchange without establishing a connection.

 0 | Flag(0xFF)
---|--------
 1 | Length
2-4|  Salt
5-7|  HMAC

## Thanks
openssl-key-exchange builds on the efforts of fantastic C++ projects. In no particular order:
* [rpclib](https://github.com/rpclib/rpclib)
* [openssl](https://github.com/openssl/openssl)
* [protobuf](https://github.com/protocolbuffers/protobuf)