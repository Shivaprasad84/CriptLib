#include "cryptlib.hpp"
#include <iostream>
#include <vector>

using namespace std;

int main()
{
    Crypto c;

    // string plaintext = "Attack at Dawn";
    // c.write_to_file("plaintxt.txt", plaintext);

    //*****************************************ENCRYPTION*************************************************//

    // string read_plaintxt = c.read_from_file("plaintxt.txt");
    // int c_key = 10;
    // string caesar_enc = c.caesar_encrypt(read_plaintxt, c_key);
    // c.write_to_file("caesar_enc.txt", caesar_enc);

    // string read_caesar_enc = c.read_from_file("caesar_enc.txt");
    // string vigenere_key = "Gold";
    // string vigenere_enc = c.vigenere_encrypt(read_caesar_enc, vigenere_key);
    // c.write_to_file("vigenere_enc.txt", vigenere_enc);

    // string read_vigenere = c.read_from_file("vigenere_enc.txt");
    // string atbash_enc = c.atbash_encrypt(read_vigenere);
    // c.write_to_file("atbash_enc.txt", atbash_enc);

    // string to_hex = c.read_from_file("atbash_enc.txt");
    // string hex = c.to_hex(to_hex);
    // c.write_to_file("hexfile.txt", hex);

    string msg = "Hello world 1234567890";
    string key = "Avengers";
    string enc = c.xorcipher_encrypt(msg, key);
    cout << "Encrypted: " << enc << endl;
    string dec = c.xorcipher_decrypt(enc, key);
    cout << "Decrypted: " << dec << endl;

    // Public Key: 17919
    // Private Key: 22679
    // n: 59989

    // int privkey, pubkey, n;
    // privkey = pubkey = n = 0;
    // c.genkeys_and_n(pubkey, privkey, n);
    // cout << "Public Key: " << pubkey << endl;
    // cout << "Private Key: " << privkey << endl;
    // cout << "n: " << n << endl;

    // string read_atbash_enc = c.read_from_file("hexfile.txt");
    // vector<unsigned int> rsa_enc = c.rsa_encrypt(read_atbash_enc, 17919, 59989);
    // c.write_rsa_encryption_file("rsa_enc.txt", rsa_enc);

    //****************************END OF ENCRYPTION****************************************//

    //*******************************DECRYPTION**********************************************//

    // vector<unsigned int> read_rsa_enc = c.read_rsa_encryption_file("rsa_enc.txt");
    // string rsa_dec = c.rsa_decrypt(read_rsa_enc, 22679, 59989);
    // cout << "RSA Decryption: " << rsa_dec << endl;
    // string unicode = c.to_unicode(rsa_dec);
    // cout << "Hex Decryption: " << unicode << endl;
    // string atbash_dec = c.atbash_decrypt(unicode);
    // cout << "Atbash Decryption: " << atbash_dec << endl;
    // string vigenere_dec = c.vigenere_decrypt(atbash_dec, "Gold");
    // cout << "Vigenere Decryption: " << vigenere_dec << endl;
    // string caesar_dec = c.caesar_decrypt(vigenere_dec, 10);
    // cout << "Caesar Decryption: " << caesar_dec << endl;
    // c.write_to_file("decrypt.txt", caesar_dec);

    //****************************END OF DECRYPTION*******************************************************//
}