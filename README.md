# DES_SystemVerilog
Data Encryption Standard system implemented in SystemVerilog

Goal: Input 64-bit number (plaintext) and 64-bit key for encryption/decryption, output as ciphertext.

DES
genSubkeys
initial permutation on plaintext
round 1-16 permutations on plaintext using subkeys
final permutation on plaintext -> ciphertext


genSubkeys
PC1 on input key
left-shift output
PC2 on shifted output -> subkey1
left-shift shifted output
PC2 on shifted output -> subkey2
...
left-shift shifted output
PC2 on shifted output -> subkey16


round
left half of output = right half of input
feistel function using right half of input and the subkey
XOR output with the left half of input -> round output


feistel 
expand function on input
XOR expand output with the subkey
S function on XOR'd output
straight function on S output -> feistel output


further documentation on initial permutation, final permutation, pc1, pc2, expand, s, and straight located at
https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
