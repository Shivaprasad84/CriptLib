#include <iostream>
#include <vector>
#include <stdlib.h>
#include <fstream>
#include "cryptlib.hpp"
#include "stack.hpp"

using namespace std;

string sequence_str = "Encryption Sequence: ";
Crypto c;
vector<int> integer_keys;
vector<string> string_keys;
namespace crypt_file
{
bool is_empty(ifstream &file)
{
    return file.peek() == ifstream::traits_type::eof();
}
} // namespace crypt_file

//*********************************************ENCRYPTION**************************************************//

void caesar_encrypt()
{
    ifstream file("information.txt");
    string msg, enc, k;
    if (crypt_file::is_empty(file))
    {
        cout << "Enter a message to encrypt: ";
        cin.get();
        getline(cin, msg);
        c.write_to_file("plaintxt.txt", msg);
    }
    else
    {
        msg = c.read_from_file("information.txt");
    }
    cout << "Enter a key(integer) for caesar encryption: ";
    cin >> k;
    sequence_str += k + "; ";
    int key = stoi(k);
    enc = c.caesar_encrypt(msg, key);
    cout << "\n\t\t\t\t   Caesar Encryption Completed\n" << endl;
    c.write_to_file("caesar_enc.txt", enc);
    c.write_to_file("information.txt", enc);
}

void vigenere_encrypt()
{
    ifstream file("information.txt");
    string msg, key, enc;
    if (crypt_file::is_empty(file))
    {
        cout << "Enter a message to encrypt: ";
        cin.get();
        getline(cin, msg);
        c.write_to_file("plaintxt.txt", msg);
    }
    else
    {
        msg = c.read_from_file("information.txt");
    }
    cout << "Enter a key(word) for vigenere encryption: ";
    cin >> key;
    sequence_str += key + "; ";
    enc = c.vigenere_encrypt(msg, key);
    cout << "\n\t\t\t\t   Vigenere Encryption Completed\n" << endl;
    c.write_to_file("vigenere_enc.txt", enc);
    c.write_to_file("information.txt", enc);
}

void atbash_encrypt()
{
    ifstream file("information.txt");
    string msg, enc;
    if (crypt_file::is_empty(file))
    {
        cout << "Enter a message to encrypt: ";
        cin.get();
        getline(cin, msg);
        c.write_to_file("plaintxt.txt", msg);
    }
    else
    {
        msg = c.read_from_file("information.txt");
    }
    enc = c.atbash_encrypt(msg);
    cout << "\n\t\t\t\t   Atbash Encryption Completed\n" << endl;
    c.write_to_file("atbash_enc.txt", enc);
    c.write_to_file("information.txt", enc);
}

void xor_encrypt()
{
    ifstream file("information.txt");
    string msg, enc, key;
    if (crypt_file::is_empty(file))
    {
        cout << "Enter a message to encrypt: ";
        cin.get();
        getline(cin, msg);
        c.write_to_file("plaintxt.txt", msg);
    }
    else
    {
        msg = c.read_from_file("information.txt");
    }
    cout << "Enter a key(word) for xor encryption: ";
    cin >> key;
    sequence_str += key + "; ";
    enc = c.xorcipher_encrypt(msg, key);
    cout << "\n\t\t\t\t   Xor Encryption Completed\n" << endl;
    c.write_to_file("xor_enc.txt", enc);
    c.write_to_file("information.txt", enc);
}

//*************************************************DECRYPTION****************************************************************//

void caesar_decrypt()
{
    string enc = c.read_from_file("information.txt");
    int key = integer_keys.at(integer_keys.size() - 1);
    integer_keys.pop_back();
    string dec = c.caesar_decrypt(enc, key);
    c.write_to_file("information.txt", dec);
    c.write_to_file("caesar_dec.txt", dec);
}

void vigenere_decrypt()
{
    string enc = c.read_from_file("information.txt");
    string key = string_keys.at(string_keys.size() - 1);
    string_keys.pop_back();
    string dec = c.vigenere_decrypt(enc, key);
    c.write_to_file("information.txt", dec);
    c.write_to_file("vigenere_dec.txt", dec);
}

void atbash_decrypt()
{
    string enc = c.read_from_file("information.txt");
    string dec = c.atbash_decrypt(enc);
    c.write_to_file("information.txt", dec);
    c.write_to_file("atbash_dec.txt", dec);
}

void xor_decrypt()
{
    string enc = c.read_from_file("information.txt");
    string key = string_keys.at(string_keys.size() - 1);
    string_keys.pop_back();
    string dec = c.xorcipher_decrypt(enc, key);
    c.write_to_file("information.txt", dec);
    c.write_to_file("xor_dec.txt", dec);
}

//************************************************************************************************************************************//

int main()
{
    int choice;
    system("clear");
    cout << endl; 
    cout << "\t\t\t\t\tWelcome To CryptLib" << endl;
    cout << "\t\t\t\t\t------- -- --------" << endl;
    cout << endl;
    cout << "\t\t\t\t\t1. Encryption" << endl;
    cout << "\t\t\t\t\t2. Decryption" << endl;
    cout << "\t\t\t\t\t3. Generate RSA keys" << endl;
    cout << "\t\t\t\t\t4. Exit" << endl;
    cin >> choice;
    if (choice == 1)
    {
        // Encryption
        int level;
        cout << endl;
        cout << "\t\t\t\t\t1. Caesar Cipher" << endl;
        cout << "\t\t\t\t\t2. Vigenere Cipher" << endl;
        cout << "\t\t\t\t\t3. Atbash Cipher" << endl;
        cout << "\t\t\t\t\t4. Xor Cipher" << endl;
        cout << endl;
        cout << "Enter the level of encryption: ";
        cin >> level;
        cout << "\nEnter " << level << " number(s): " << endl;
        vector<int> enc_sequence(level);
        for (int i = 0; i < level; i++)
        {
            int temp;
            cin >> temp;
            enc_sequence.push_back(temp);
        }

        for (int i : enc_sequence)
        {
            switch (i)
            {
            case 1:
            {
                // Caesar Cipher
                sequence_str += "(1)Caesar Cipher: key = ";
                caesar_encrypt();
                break;
            }
            case 2:
            {
                // Vigenere Cipher
                sequence_str += "(2)Vigenere Cipher: key = ";
                vigenere_encrypt();
                break;
            }
            case 3:
            {
                // Atbash Cipher
                sequence_str += "(3)Atbash Cipher; ";
                atbash_encrypt();
                break;
            }
            case 4:
            {
                // Xor Cipher
                sequence_str += "(4)Xor Cipher: key = ";
                xor_encrypt();
                break;
            }
            }
        }
        unsigned int public_key, n;
        cout << "\n(RSA Encryption)Enter public key: ";
        cin >> public_key;
        cout << "Enter n: ";
        cin >> n;
        vector<unsigned int> sequence = c.rsa_encrypt(sequence_str, public_key, n);
        c.write_rsa_encryption_file("sequence_file.txt", sequence);
    }
    else if (choice == 2)
    {
        // Decryption
        int private_key, n;
        cout << "Enter private key: ";
        cin >> private_key;
        cout << "Enter n: ";
        cin >> n;
        vector<unsigned int> sequence = c.read_rsa_encryption_file("sequence_file.txt");
        string sequence_dec = c.rsa_decrypt(sequence, private_key, n);
        c.write_to_file("sequence_file.txt", sequence_dec);

        stack s;
        int level;
        cout << endl;
        cout << "\t\t\t\t\t1. Caesar Cipher" << endl;
        cout << "\t\t\t\t\t2. Vigenere Cipher" << endl;
        cout << "\t\t\t\t\t3. Atbash Cipher" << endl;
        cout << "\t\t\t\t\t4. Xor Cipher" << endl;
        cout << endl;
        cout << "Enter the level of decryption: ";
        cin >> level;
        cout << "\nEnter " << level << " number(s): " << endl;
        for (int i = 0; i < level; i++)
        {
            int seq_id;
            cin >> seq_id;
            switch (seq_id)
            {
            case 1:
            {
                int t;
                cout << "Enter Caesar Key: ";
                cin >> t;
                integer_keys.push_back(t);
                break;
            }
            case 2:
            {
                string temp;
                cout << "Enter Vigenere Cipher Key: ";
                cin >> temp;
                string_keys.push_back(temp);
                break;
            }
            case 3:
            {
                cout << "No key for Atbash Cipher" << endl;
                break;
            }
            case 4:
            {
                string temp;
                cout << "Enter XOR Cipher Key: ";
                cin >> temp;
                string_keys.push_back(temp);
                break;
            }
            }
            s.push(seq_id);
        }

        for (int i = 0; i < level; i++)
        {
            int seq_id = s.pop();
            switch (seq_id)
            {
            case 1:
            {
                // Caesar Cipher
                caesar_decrypt();
                break;
            }
            case 2:
            {
                // Vigenere Cipher
                vigenere_decrypt();
                break;
            }
            case 3:
            {
                // Atbash Cipher
                atbash_decrypt();
                break;
            }
            case 4:
            {
                // Xor Cipher
                xor_decrypt();
                break;
            }
            }
        }
    }
    else if (choice == 3)
    {
        //Generate Keys and n
        int private_key, public_key, n;
        private_key = public_key = n = 0;
        c.genkeys_and_n(public_key, private_key, n);
        cout << "Private key: " << private_key << endl;
        cout << "Public key : " << public_key << endl;
        cout << "n          : " << n << endl;
    }
    else if(choice == 4)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        cout << "Invalid Choice! Try Again" << endl;
    }
}