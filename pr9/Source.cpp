#include "Header.h"

bool ElGamal::IsPrimitiveRoot(const Integer& a)
{
    if (a_exp_b_mod_c(g, order, p) != 1)
    {
        return false;
    }

    for (Integer q = 2; q * q <= order; q++)
    {
        if (order % q == 0)
        {
            if (a_exp_b_mod_c(a, order / q, p) == 1)
            {
                return false;
            }
        }
    }

    return true;
}

Integer ElGamal::ModularInverse(const Integer& a, const Integer& m)
{
    Integer result = a.InverseMod(m);
    if (result == Integer::Zero()) 
    {
        throw runtime_error("Inverse does not exist");
    }

    return result;
}

void ElGamal::GenerateRelativelyPrime(Integer& a)
{
    Integer max = order - 1;

    do 
    {
        a.Randomize(rng, 1, max);
    }
    while (GCD(a, order) != 1);
}

void ElGamal::GenerateRandomElement(Integer& a)
{
    Integer x(rng, Integer::One(), order);

    a = a_exp_b_mod_c(g, x, p);
}

void ElGamal::MessageToHash(string message, Integer& hash_num)
{
    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE];

    hash.Update((const byte*)message.data(), message.size());
    hash.Final(digest);
    hash_num.Decode(digest, hash.DigestSize());

    if (hash_num > p)
    {
        throw runtime_error("Hash value > p");
    }
}

ElGamal::ElGamal()
{
    //generate a random prime number p
    AlgorithmParameters params = MakeParameters("BitLength", 32)
        ("RandomNumberType", Integer::PRIME);

    p.GenerateRandom(rng, params);

    cout << "p = " << p << endl;

    order = p - 1;

    //calculate primitive root of the module p
    while (!IsPrimitiveRoot(g)) 
    {
        g.Randomize(rng, 2, order);
    }

    cout << "g = " << g << endl;
}

void ElGamal::GenerateKeys(tuple<Integer, Integer>& key_pair)
{
    //gen random number a (private key)
    get<0>(key_pair).Randomize(rng, Integer::One(), order);

    cout << "a = " << get<0>(key_pair) << endl;

    //calculate the public key b
    get<1>(key_pair) = a_exp_b_mod_c(g, get<0>(key_pair), p);

    cout << "b = " << get<1>(key_pair) << endl;
}

void ElGamal::Signature(string message, const Integer& a, tuple<Integer, Integer>& signature)
{
    Integer k;

    //gen random number k
    GenerateRelativelyPrime(k);

    cout << "k = " << k << endl;

    //calculate the first component of the signature: r = g^k mod p
    get<0>(signature) = a_exp_b_mod_c(g, k, p);

    cout << "r = " << get<0>(signature) << endl;

    //calculate the hash value of the message (p is too small for any hash value so h = 32123)
    Integer h = 32123;
    //MessageToHash(message, h);

    cout << "hash = " << h << endl;

    //calculate the second component of the signature: s = (H(m) - a*r) * k^(-1) mod(p - 1)
    get<1>(signature) = ((h - a * get<0>(signature)) * ModularInverse(k, order)) % order;

    cout << "s = " << get<1>(signature) << endl;
}

bool ElGamal::Verification(const Integer& b, const tuple<Integer, Integer>& signature, string message)
{
    if (get<0>(signature) < 0 || get<0>(signature) > p 
        || get<1>(signature) < 0 || get<1>(signature) > order)
    {
        cout << "Failed: 0 < r < p || 0 < s < p - 1" << endl;
        return false;
    }

    //calculate the hash value of the message (p is too small for any hash value so h = 32123)
    Integer h = 32123;
    //MessageToHash(message, h);

    cout << "hash = " << h << endl;

    Integer ur = a_exp_b_mod_c(b, get<0>(signature), p) * a_exp_b_mod_c(get<0>(signature), get<1>(signature), p) % p;
    Integer ul = a_exp_b_mod_c(g, h, p);

    cout << ur << " == " << ul << " (g^r * r^s == g^h)" << endl;
    
    return ur == ul;
}
