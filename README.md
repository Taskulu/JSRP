
## JSRP

SRP for java that compatible with [jsrp](https://github.com/alax/jsrp)(node-srp) and [sirp](https://github.com/grempe/sirp)(ruby)

Only support <b>4096 Primes</b> with <b>G</b> equals to <b>5</b> and use <b>SHA-256</b> for message digest
## Code Example

#### Login with SRP
```java
String identifier = "username";
String password = "password";

// Create client
Client mClient = new Client(identifier,password);

// Get A
String A = mClient.getPublicKey();

// Send A to server, server will returns B and salt
// User B and salt for creating M1

String M1 = mClient.getProof(B,salt);

// Send M1 to server to verify your identity

```

#### Create Verifier and Salt with SRP
```java
String identifier = "username";
String password = "password";

// Create client
Client mClient = new Client(identifier,password);

// Call createVerifier
Verifier result = mClient.createVerifier();

// Salt
result.getSalt();
// Verifier
result.getVerifier();

```

## Tests

Soon ...

## Todo

##### Implement Server
##### Write integration test between Client and Server
##### Add other primes and hash digest

## License

MIT License

Copyright (c) 2016 Taskulu
