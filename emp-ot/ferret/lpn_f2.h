#ifndef EMP_LPN_F2K_H__
#define EMP_LPN_F2K_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/role.h"

using namespace emp;


// Implementation of local linear code on F_2^k
// Performance highly dependent on the CPU cache size
template<Role role, int d = 10>
void sparse_linear_code(
    const MpDesc& desc, const std::bitset<128>& seed, int threads,
    std::span<std::bitset<128>> nn,
    std::span<const std::bitset<128>> kk) {

  const auto task = [=](int start, int end) {
    PRP prp(*(const block*)&seed);
    int j = start;
    std::bitset<128> tmp[10];
    for (; j < end-4; j+=4) {
      for (int m = 0; m < 10; ++m) {
        tmp[m] = std::bitset<128> { static_cast<unsigned long long>((j << 8) + m) };
      }
      AES_ecb_encrypt_blks((block*)tmp, 10, &prp.aes);
      uint32_t* r = reinterpret_cast<uint32_t*>(tmp);
      for (int m = 0; m < 4; ++m) {
        for (int ix = 0; ix < d; ++ix) {
          /* int index = r[m*d + ix] % desc.k; */
          int index = (*r) & desc.mask;
          ++r;
          index = index >= desc.k ? index-desc.k : index;
          nn[j+m] = nn[j+m] ^ kk[index];
        }
      }
    }
    for (; j < end; ++j) {
      for (int m = 0; m < 3; ++m) {
        tmp[m] = std::bitset<128> { static_cast<unsigned long long>((j << 8) + m) };
      }
      AES_ecb_encrypt_blks((block*)tmp, 3, &prp.aes);
      uint32_t* r = (uint32_t*)(tmp);
      for (int ix = 0; ix < d; ++ix) {
        nn[j] = nn[j] ^ kk[r[ix]%desc.k];
      }
    }
  };

  int width = desc.n/(threads+1);
  std::vector<std::thread> ths;
  for (int i = 0; i < threads+1; ++i) {
    int start = i * width;
    int end = min((std::size_t)(i+1)* width, desc.n);
    ths.emplace_back(std::thread { [&, start, end]() { task(start, end); } });
  }

  for (auto& th: ths) { th.join(); }
}

#endif
