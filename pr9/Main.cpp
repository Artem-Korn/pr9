#include "Header.h"

int main()
{
    cout << "Constructor()" << endl;
    ElGamal a;

    string message = "test";
    tuple<Integer, Integer> key_pair;
    tuple<Integer, Integer> signature;

    cout << "GenerateKeys()" << endl;
    a.GenerateKeys(key_pair);

    cout << "Signature()" << endl;
    a.Signature(message, get<0>(key_pair), signature);

    cout << "Verification()" << endl;
    cout << "result: " << a.Verification(get<1>(key_pair), signature, message) << endl;
}