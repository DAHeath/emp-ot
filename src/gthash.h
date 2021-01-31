#ifndef GT_HASH_H__
#define GT_HASH_H__

#include <bitset>
#include <openssl/sha.h>
#include <immintrin.h>

inline
std::bitset<128> hash(const void* data, std::size_t nbyte) {
  std::bitset<128> digest[2];
  SHA256((const unsigned char *)data, nbyte, (unsigned char *)digest);
  return digest[0];
}

#endif
