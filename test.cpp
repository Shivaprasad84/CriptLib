#include "cryptlib.hpp"
#include <iostream>
#include <vector>

using namespace std;

int main()
{
    Crypto c;

    // int privkey, pubkey, n;
    // privkey = pubkey = n = 0;
    // c.genkeys_and_n(pubkey, privkey, n);
    // cout << "Public Key: " << pubkey << endl;
    // cout << "Private Key: " << privkey << endl;
    // cout << "n: " << n << endl;


    // string msg_to_enc = c.read_from_file("plaintxt.txt");
    // string caes_enc = c.caesar_encrypt(msg_to_enc, 6);

    // vector<unsigned int> vec = c.rsa_encrypt(caes_enc, 26251, 59989);
    // c.write_rsa_encryption_file("cryptfile.txt", vec);

    // vector<unsigned int> v = c.read_rsa_encryption_file("cryptfile.txt");
    // string dec_msg = c.rsa_decrypt(v, -8749, 59989);
    // c.write_to_file("decrypt.txt", dec_msg);

    string x = c.read_from_file("decrypt.txt");
    string y = c.caesar_decrypt(x, 6);

    c.write_to_file("decrypt1.txt", y);




    // string msg;
    // int key;
    // cout << "Enter a message: ";
    // getline(cin, msg);
    // cout << "Enter a key: ";
    // cin >> key;
    // string enc_msg = c.caesar_encrypt(msg, key);

    // cout << "Encrypted message: " << enc_msg << endl;

    // string dec_msg = c.caesar_decrypt(enc_msg, key);

    // cout << "Decrypted message: " << dec_msg << endl;
}