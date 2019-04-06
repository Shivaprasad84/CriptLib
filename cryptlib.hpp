#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <algorithm>

class Crypto
{
private:
  std::string c_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  std::string l_alpha = "abcdefghijklmnopqrstuvwxyz";
  std::string nums = "0123456789";
  const unsigned int gcd(unsigned int a, unsigned int b);

  const unsigned int extEuclid(unsigned int x, unsigned int y, int *d, int *k);

  unsigned int Exp_n_Mod(int base, int exp, unsigned int n);

  bool is_lower(char x);

  bool is_upper(char x);

  bool is_num(char x);

public:
  Crypto();
  void genkeys_and_n(int &e, int &d, int &n);

  std::vector<unsigned int> rsa_encrypt(const std::string& msg, int pubKey, int rem);

  std::string rsa_decrypt(std::vector<unsigned int> crypt_arr, int privKey, int rem);

  std::string caesar_encrypt(const std::string& msg, int key);

  std::string caesar_decrypt(const std::string& enc, int key);

  std::string vigenere_encrypt(const std::string& msg, const std::string& key);

  std::string vigenere_decrypt(const std::string& enc, const std::string& key);

  std::string atbash_encrypt(const std::string& msg);

  std::string atbash_decrypt(const std::string& enc);

  std::string xorcipher_encrypt(const std::string& msg, const std::string& key);

  std::string xorcipher_decrypt(const std::string& enc, const std::string& key);

  std::string to_hex(const std::string &msg);

  std::string to_unicode(const std::string &msg);



  void write_to_file(const std::string &fname, const std::string &data);

  void write_rsa_encryption_file(const std::string &fname, std::vector<unsigned int> &data);

  std::string read_from_file(const std::string &fname);

  std::vector<unsigned int> read_rsa_encryption_file(const std::string &fname);

  std::string sanitize_str(const std::string& str);
};