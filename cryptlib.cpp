#include "cryptlib.hpp"

typedef unsigned int uint;
Crypto::Crypto()
{
    srand(time(NULL));
}

//************************************************************** RSA ***********************************************************//

const uint Crypto::gcd(uint a, uint b)
{
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

const uint Crypto::extEuclid(uint x, uint y, int *d, int *k)
{
    uint sa = 1, ta = 0, sb = 0, tb = 1, q, tempA, tempB;
    int a = x, b = y;
    while (b > 0)
    {
        q = a / b;
        tempA = a;
        a = b;
        b = tempA - q * b;
        tempA = sa;
        tempB = ta;
        sa = sb;
        ta = tb;
        sb = tempA - q * sb;
        tb = tempB - q * tb;
    }
    *d = sa;
    *k = ta;
    return a;
}

uint Crypto::Exp_n_Mod(int base, int exp, uint n)
{
    while (base < 0)
        base += n;
    if (exp < 0)
    {
        int temp = 0;
        extEuclid(base, n, &base, &temp);
        return Exp_n_Mod(base, -1 * exp, n);
    }
    uint res = 1;
    base = base % n;
    while (exp > 0)
    {
        if (exp & 1)
            res = (res * base) % n;
        exp = exp >> 1;
        base = (base * base) % n;
    }
    return res;
}

void Crypto::genkeys_and_n(int &e, int &d, int &n)
{
    uint p = 239, q = 251; // Two Large primes
    n = p * q;
    uint phi = (p - 1) * (q - 1); // Euler Totient
    uint pubKey;
    do
    {
        pubKey = rand() % phi;
    } while (gcd(pubKey, phi) != 1);
    e = pubKey;

    int privKey, k;
    extEuclid(pubKey, phi, &privKey, &k);
    d = privKey;
}

std::vector<uint> Crypto::rsa_encrypt(const std::string &msg, int pubKey, int rem)
{
    std::string x = "";
    std::vector<uint> crypt_arr(msg.size());
    for (int i = 0; i < msg.size(); i++)
    {
        uint temp = Exp_n_Mod((uint)msg[i], pubKey, rem);
        crypt_arr.at(i) = temp;
    }
    return crypt_arr;
}

std::string Crypto::rsa_decrypt(std::vector<uint> crypt_arr, int privKey, int rem)
{
    std::string dec_msg = "";
    int len = crypt_arr.size();
    for (int i = 0; i < len; i++)
    {
        dec_msg += (char)(Exp_n_Mod(crypt_arr[i], privKey, rem));
    }
    return dec_msg;
}

//****************************************** Utilities ***************************************************************************//

bool Crypto::is_lower(char x)
{
    int temp = (int)x;
    return temp >= 97 && temp <= 122;
}

bool Crypto::is_upper(char x)
{
    int temp = (int)x;
    return temp >= 65 && temp <= 90;
}

bool Crypto::is_num(char x)
{
    int temp = (int)x;
    return temp >= '0' && temp <= '9';
}

std::string Crypto::to_hex(const std::string &msg)
{
    std::stringstream res;
    for (int i = 0; i < msg.size(); i++)
    {
        res << std::hex << std::setfill('0') << std::setw(2) << ((int)msg[i]);
    }
    std::string hex;
    res >> hex;
    return hex;
}

std::string Crypto::to_unicode(const std::string &msg)
{
    std::string unicode;
    for (int i = 0; i < msg.size() - 1; i += 2)
    {
        std::string op = msg.substr(i, 2);
        int decimal = std::stoi(op, 0, 16);
        unicode += (char)decimal;
    }
    return unicode;
}

//******************************************************* Caesar Cipher ************************************************************//

std::string Crypto::caesar_encrypt(const std::string &msg, int key)
{
    std::string enc = "";
    for (int i = 0; i < msg.size(); i++)
    {
        if (is_upper(msg[i]))
        {
            enc += c_alpha[(((int)msg[i] - 65) + key) % 26];
        }
        else if (is_lower(msg[i]))
        {
            enc += l_alpha[(((int)msg[i] - 97) + key) % 26];
        }
        else if (is_num(msg[i]))
        {
            enc += nums[(((int)msg[i] - 48) + key) % 10];
        }
        else
        {
            enc += msg[i];
        }
    }
    return enc;
}

std::string Crypto::caesar_decrypt(const std::string &enc, int key)
{
    std::string dec = "";
    int temp;
    for (int i = 0; i < enc.size(); i++)
    {
        if (is_upper(enc[i]))
        {
            temp = (int)enc[i] - 65 - key;
            while (temp < 0)
                temp += 26;
            dec += c_alpha[temp % 26];
        }
        else if (is_lower(enc[i]))
        {
            temp = (int)enc[i] - 97 - key;
            while (temp < 0)
                temp += 26;
            dec += l_alpha[temp % 26];
        }
        else if (is_num(enc[i]))
        {
            temp = (int)enc[i] - 48 - key;
            while (temp < 0)
                temp += 10;
            dec += nums[temp % 10];
        }
        else
        {
            dec += enc[i];
        }
    }
    return dec;
}

//******************************************************* Vigenere Cipher ************************************************************//

std::string Crypto::vigenere_encrypt(const std::string &msg, const std::string &key)
{
    std::string enc = "";
    for (int i = 0; i < msg.size(); i++)
    {
        char m = msg[i];
        char k = key[i % key.size()];
        if (is_upper(m))
        {
            if (is_upper(k))
            {
                enc += c_alpha[((int)m - 65 + (int)k - 65) % 26];
            }
            else if (is_lower(k))
            {
                enc += c_alpha[((int)m - 65 + (int)k - 97) % 26];
            }
        }
        else if (is_lower(m))
        {
            if (is_upper(k))
            {
                enc += l_alpha[((int)m - 97 + (int)k - 65) % 26];
            }
            else if (is_lower(k))
            {
                enc += l_alpha[((int)m - 97 + (int)k - 97) % 26];
            }
        }
        else if (is_num(m))
        {
            if (is_upper(k))
            {
                enc += nums[((int)m - 48 + (int)k - 65) % 10];
            }
            else if (is_lower(k))
            {
                enc += nums[((int)m - 48 + (int)k - 97) % 10];
            }
        }
        else
        {
            enc += msg[i];
        }
    }
    return enc;
}

std::string Crypto::vigenere_decrypt(const std::string &enc, const std::string &key)
{
    std::string dec = "";
    int temp;
    for (int i = 0; i < enc.size(); i++)
    {
        char e = enc[i];
        char k = key[i % key.size()];
        if (is_upper(e))
        {
            if (is_upper(k))
            {
                temp = (int)e - 65 - ((int)k - 65);
                while (temp < 0)
                    temp += 26;
                dec += c_alpha[temp % 26];
            }
            else if (is_lower(k))
            {
                temp = (int)e - 65 - ((int)k - 97);
                while (temp < 0)
                    temp += 26;
                dec += c_alpha[temp % 26];
            }
        }
        else if (is_lower(e))
        {
            if (is_upper(k))
            {
                temp = (int)e - 97 - ((int)k - 65);
                while (temp < 0)
                    temp += 26;
                dec += l_alpha[temp % 26];
            }
            else if (is_lower(k))
            {
                temp = (int)e - 97 - ((int)k - 97);
                while (temp < 0)
                    temp += 26;
                dec += l_alpha[temp % 26];
            }
        }
        else if (is_num(e))
        {
            if (is_upper(k))
            {
                temp = (int)e - 48 - ((int)k - 65);
                while (temp < 0)
                    temp += 10;
                dec += nums[temp % 10];
            }
            else if (is_lower(k))
            {
                temp = (int)e - 48 - ((int)k - 97);
                while (temp < 0)
                    temp += 10;
                dec += nums[temp % 10];
            }
        }
        else
        {
            dec += enc[i];
        }
    }
    return dec;
}

//****************************************************ATBASH CIPHER****************************************************************//

std::string Crypto::atbash_encrypt(const std::string &msg)
{
    std::string enc = "";
    for (int i = 0; i < msg.size(); i++)
    {
        if (is_upper(msg[i]))
        {
            enc += c_alpha[25 - ((int)msg[i] - 65)];
        }
        else if (is_lower(msg[i]))
        {
            enc += l_alpha[25 - ((int)msg[i] - 97)];
        }
        else if (is_num(msg[i]))
        {
            enc += nums[9 - ((int)msg[i] - 48)];
        }
        else
        {
            enc += msg[i];
        }
    }
    return enc;
}

std::string Crypto::atbash_decrypt(const std::string &enc)
{
    std::string dec = "";
    for (int i = 0; i < enc.size(); i++)
    {
        if (is_upper(enc[i]))
        {
            dec += c_alpha[25 - ((int)enc[i] - 65)];
        }
        else if (is_lower(enc[i]))
        {
            dec += l_alpha[25 - ((int)enc[i] - 97)];
        }
        else if (is_num(enc[i]))
        {
            dec += nums[9 - ((int)enc[i] - 48)];
        }
        else
        {
            dec += enc[i];
        }
    }
    return dec;
}

//**************************************************XORCIPHER**********************************************************************//

std::string Crypto::xorcipher_encrypt(const std::string &msg, const std::string &key)
{
    std::string enc;
    std::stringstream res;
    for (int i = 0; i < msg.size(); i++)
    {
        int temp = (int)msg[i] ^ (int)key[i % key.size()];
        res << std::hex << std::setfill('0') << std::setw(2) << temp;
    }
    res >> enc;
    return enc;
}

std::string Crypto::xorcipher_decrypt(const std::string &enc, const std::string &key)
{
    std::string dec, de;
    for (int i = 0; i < enc.size() - 1; i += 2)
    {
        std::string op = enc.substr(i, 2);
        int decimal = std::stoi(op, 0, 16);
        de += (char)decimal;
    }

    for (int i = 0; i < de.size(); i++)
    {
        int temp = (int)de[i] ^ (int)key[i % key.size()];
        dec += (char)temp;
    }
    return dec;
}

//***************************************COLUMNAR TRANSPOSITION CIPHER*************************************************************//

std::string Crypto::key_to_num(const std::string &key)
{
    std::string num_key;
    std::string k = key;
    std::sort(k.begin(), k.end());
    for (int i = 0; i < k.size(); i++)
    {
        num_key += (char)((k.find(key[i]) + 1) + 48);
    }
    return num_key;
}

std::string Crypto::ct_encrypt(const std::string &msg, const std::string &key)
{
    std::string enc;
    std::string k = key_to_num(key);
    int k_size = k.size();
    int r = (msg.length() / k_size) + 1;
    char **mat = new char *[r];
    for (int i = 0; i < r; i++)
    {
        mat[i] = new char[k_size];
    }

    std::vector<int> vec(k_size);
    for (int i = 0; i < k_size; i++)
    {
        vec.at(i) = (int)k[i] - 48;
    }

    int x = 0;
    for (int i = 0; i < r; i++)
    {
        for (int j = 0; j < k_size; j++)
        {
            if (!msg[x])
            {
                mat[i][j] = '`';
            }
            else if (msg[x] == ' ')
            {
                mat[i][j] = '`';
            }
            else
            {
                mat[i][j] = msg[x];
            }
            x++;
        }
    }

    for (int i = 0; i < k_size; i++)
    {
        for (int j = 0; j < r; j++)
        {
            enc += mat[j][vec[i] - 1];
        }
    }
    return enc;
}

std::string Crypto::ct_decrypt(const std::string &enc, const std::string &key)
{
    std::string dec;
    std::string k = key_to_num(key);
    int k_size = k.size();
    std::vector<int> vec(k_size);
    for (int i = 0; i < k_size; i++)
    {
        vec.at(i) = (int)k[i] - 48;
    }

    int r = (enc.length() / k_size);
    char **mat = new char *[r];
    for (int i = 0; i < r; i++)
    {
        mat[i] = new char[k_size];
    }

    int x = 0;
    for (int i = 0; i < k_size; i++)
    {
        for (int j = 0; j < r; j++)
        {
            if (!enc[x])
            {
                mat[j][i] = '`';
            }
            else if (enc[i] == ' ')
            {
                mat[j][vec[i] - 1] = '`';
            }
            else
            {
                mat[j][vec[i] - 1] = enc[x];
            }
            x++;
        }
    }

    for (int i = 0; i < r; i++)
    {
        for (int j = 0; j < k_size; j++)
        {
            dec += mat[i][j];
        }
    }
    std::string decrypted = "";
    for(int i = 0; i < dec.size(); i++)
    {
        char temp = dec[i];
        decrypted += (temp == '`') ?  ' ' : dec[i];
    }
    return decrypted;
}

// ************************************************* File I/O **********************************************************************//

void Crypto::write_to_file(const std::string &fname, const std::string &data)
{
    std::ofstream file(fname);
    if (file.is_open())
    {
        for (int i = 0; i < data.size(); i++)
        {
            file << data.at(i);
        }
    }
    file.close();
}

void Crypto::write_rsa_encryption_file(const std::string &fname, std::vector<uint> &data)
{
    std::ofstream file(fname);
    if (file.is_open())
    {
        for (int i = 0; i < data.size(); i++)
        {
            file << data.at(i);
            file << " ";
        }
    }
    file.close();
}

std::string Crypto::read_from_file(const std::string &fname)
{
    std::string word;
    std::string msg = "";
    std::ifstream file(fname);
    if (file.is_open())
    {
        while (file >> word)
        {
            msg += word;
            msg += " ";
        }
    }
    file.close();
    std::string message = sanitize_str(msg);
    return message;
}

std::vector<uint> Crypto::read_rsa_encryption_file(const std::string &fname)
{
    std::string word;
    std::vector<uint> vec;
    std::ifstream file(fname);
    if (file.is_open())
    {
        while (file >> word)
        {
            vec.push_back(stoi(word));
        }
    }
    file.close();
    return vec;
}

std::string Crypto::sanitize_str(const std::string &str)
{
    std::string temp = str;
    temp.erase(std::find_if(temp.rbegin(), temp.rend(), std::bind1st(std::not_equal_to<char>(), ' ')).base(), temp.end());
    return temp;
}
