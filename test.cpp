#include "cryptlib.hpp"
#include <iostream>
#include <vector>

using namespace std;

int main()
{
    Crypto c;

    // string plaintext = "SO What!!! Pandith";
    // c.write_to_file("plaintxt.txt", plaintext);

    //*****************************************ENCRYPTION*************************************************//

    // string read_plaintxt = c.read_from_file("plaintxt.txt");
    // int c_key = 19;
    // string caesar_enc = c.caesar_encrypt(read_plaintxt, c_key);
    // c.write_to_file("caesar_enc.txt", caesar_enc);

    // string read_caesar_enc = c.read_from_file("caesar_enc.txt");
    // string vigenere_key = "Thanos";
    // string vigenere_enc = c.vigenere_encrypt(read_caesar_enc, vigenere_key);
    // c.write_to_file("vigenere_enc.txt", vigenere_enc);

    // string read_vigenere = c.read_from_file("vigenere_enc.txt");
    // string atbash_enc = c.atbash_encrypt(read_vigenere);
    // c.write_to_file("atbash_enc.txt", atbash_enc);

    // string to_hex = c.read_from_file("atbash_enc.txt");
    // string hex = c.to_hex(to_hex);
    // c.write_to_file("hexfile.txt", hex);

    // string msg = "Hello world 1234567890";
    // string key = "Avengers";
    // string enc = c.xorcipher_encrypt(msg, key);
    // cout << "Encrypted: " << enc << endl;
    // string dec = c.xorcipher_decrypt(enc, key);
    // cout << "Decrypted: " << dec << endl;

    // Public Key: 42747
    // Private Key: 10083
    // n: 59989

    // int privkey, pubkey, n;
    // privkey = pubkey = n = 0;
    // c.genkeys_and_n(pubkey, privkey, n);
    // cout << "Public Key: " << pubkey << endl;
    // cout << "Private Key: " << privkey << endl;
    // cout << "n: " << n << endl;

    // string read_atbash_enc = c.read_from_file("hexfile.txt");
    // vector<unsigned int> rsa_enc = c.rsa_encrypt(read_atbash_enc, 42747, 59989);
    // c.write_rsa_encryption_file("rsa_enc.txt", rsa_enc);

    //****************************END OF ENCRYPTION****************************************//

    //*******************************DECRYPTION**********************************************//
    //Encryption Sequence: Caesar Cipher: key = 5; Vigenere Cipher: key = Gold; Caesar Cipher: key = 4; Atbash Cipher; Xor Cipher: key = Hello;

    // string read = c.read_from_file("encryption.txt");
    // string d_one = c.xorcipher_decrypt(read, "Hello");
    // string d_two = c.atbash_decrypt(d_one);
    // string d_three = c.caesar_decrypt(d_two, 4);
    // string d_four = c.vigenere_decrypt(d_three, "Gold");
    // string d_five = c.caesar_decrypt(d_four, 5);
    // cout << d_five << endl;


    //****************************END OF DECRYPTION*******************************************************//
}