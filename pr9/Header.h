#pragma once
#include <iostream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/nbtheory.h>
#include <tuple>
using namespace std;
using namespace CryptoPP;

class ElGamal {
	Integer p;
	Integer g;
	Integer order; //p - 1
	AutoSeededRandomPool rng;

	//Check if the number is primitive root
	bool IsPrimitiveRoot(const Integer& a);
	//Get modular inverse
	Integer ModularInverse(const Integer& a, const Integer& m);
	//Generate a mutually prime number from order
	void GenerateRelativelyPrime(Integer& a);
	//Generate a random number with primitive root
	void GenerateRandomElement(Integer& a);
	//Get hash value
	void MessageToHash(string message, Integer& hash_num);

public:
	//Selecting system-wide parameters
	ElGamal();

	//Key generation
	void GenerateKeys(tuple<Integer, Integer>& key_pair);
	//Signing the message
	void Signature(string message, const Integer& a, tuple<Integer, Integer>& signature);
	//Signature verification
	bool Verification(const Integer& b, const tuple<Integer, Integer>& signature, string message);
};