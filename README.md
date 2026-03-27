# myRSA
A simple RSA API 

## Features 
- Big Signed/Unsigned Integer Classes 
- Modular Arithmatic Operations 
- Large Prime Generation
- API to generate keys and encrypt/decrpyt text files 

## Usage 

### Building 
Build using CMake
`cmake -S . -B build` 
`cmake --build build`  
*Note: Default build requires google test to be installed*

### Key Generation 
Generate a public/private key pair to files with 
`./build/keygen <public-key-file> <private-key-file>` 

### Encryption/Decryption 
Once keys have been generated encrypt/decrypt using 
`./build/encrypt <public-key-file> <message-file> <cyphertext-file>`
`./build/decrypt <private-key-file> <cyphertext-file> <message-file>`
*Note: files must be less than 256 characters in size*

## Implementation 

### Big Integers 
The unsigned integer class `uint_t<N>` is implemented using an array of `uint64_t` "limbs". The limbs are stored little-endian, so the least signifigant limb is `limbs[0]`. They can be constructed through a singular `uint64_t`, a string formatted as hexidecimal, or as a string of raw bytes. There are Arithmatic, Binary, and Logical operators. Notably, the division algorithm is an implementation of Knuth's Algorithm D, for effiency reasons. 

The signed integer class is a wrapper of the unsigned integer class, which additionally stores a boolean value for sign, and correctly applies arithmatic operations based upon it. 

There are also modular arithmetic functions to calculate modular inverses and modular exponetiation when needed for the algorithm 

### Prime Generation 
Probablistic primes are generated through a combination of low-level prime filtering and the Rabin-Miller Primality test. Candiates are checked against the first 70 prime numbers, then 10 rounds of Rabin-Miller is used. 

### RSA
Utlizes large prime generation to follow the RSA Algorithm. Keys and Encrypted messages can be stored as `uint_t<N>` or written to files. 

## Credits 
Thanks to Geeksforgeeks and phasing17 for their 64-bit int prime generation and ridiculousfish for their blog post about Knuth's Algorithm D.  




