# ISO9796SignerVerifier
Signing  BASE64 encoded plaintexts, writing the to files or stdout and verify the signature to get the original plaintext with message recovery

Wrapper for the ISO9796-2 bouncycastle (https://www.bouncycastle.org/) sign
and verify functions for Message Recovery from signatures

__ISO Standard__: [ISO_IEC_9796-2](http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf)

__Algorithm__: RSA 
__Hash__: SHA-1 
__Padding__: ISO-9796-2 Scheme 2

### Example usage: 
verify signature from file:
 java -jar -f verify -i signature.out -k publicKey.der -file
 
sign message to stdout
java -jar -f sign -i "this is the message" -k privateKey.der

### KEY GENERATION:
 
Key generations Generate a 2048-bit RSA private key 
$ openssl genrsa -out privateKey.pem 2048 

Convert privateKey to PKCS#8 format 
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in privateKey.pem -out privateKey.der -nocrypt 

Output public key in DER format
$ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

