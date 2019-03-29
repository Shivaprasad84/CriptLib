#include "cryptlib.hpp"
#include <iostream>
#include <vector>

using namespace std;

int main()
{
    Crypto c;

    int privkey, pubkey, n;
    privkey = pubkey = n = 0;
    c.genkeys_and_n(pubkey, privkey, n);
    cout << "Public Key: " << pubkey << endl;
    cout << "Private Key: " << privkey << endl;
    cout << "n: " << n << endl;

    // string msg = c.read_from_file("caesars_msg.txt");
    // string enc_msg = c.caesar_encrypt(msg, 4);

    // vector<unsigned int> vec = c.rsa_encrypt(enc_msg, 19869, 59989);
    // c.write_rsa_encryption_file("cryptfile.txt", vec);

    // vector<unsigned int> vec = c.read_rsa_encryption_file("cryptfile.txt");
    // string rdec_msg = c.rsa_decrypt(vec, 7229, 59989);
    // string cdec_msg = c.caesar_decrypt(rdec_msg, 4);
    // c.write_to_file("decrypt.txt", cdec_msg);

    // string msg = "A";
    
    // string key = "B";
    // string enc = c.vigenere_encrypt(msg, key);
    // cout << enc << endl;
    // c.write_to_file("nefile.txt", enc);
    // string en = c.read_from_file("newfile.txt");
    // string dec = c.vigenere_decrypt(en, key);
    // cout << dec << endl;
}