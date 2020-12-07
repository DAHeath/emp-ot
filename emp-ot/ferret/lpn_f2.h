#ifndef EMP_LPN_F2K_H__
#define EMP_LPN_F2K_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/role.h"

using namespace emp;


constexpr int mkMask(int k) {
  int out = 1;
  while (out < k) {
    out <<= 1;
    out = out | 0x1;
  }
  return out;
}


template <Role role>
block seed_gen(NetIO& io) {
  block seed;
  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&seed, 1);
    io.send_data(&seed, sizeof(block));
  } else {
    io.recv_data(&seed, sizeof(block));
  }
  io.flush();
  return seed;
}


//Implementation of local linear code on F_2^k
//Performance highly dependent on the CPU cache size
template<Role role, int d = 10>
void lpn(
    int n, int k, ThreadPool * pool, NetIO *io, int threads,
    block * nn, const block * kk) {

  int mask = mkMask(k);
  const block seed = seed_gen<role>(*io);

  const auto task = [nn, kk, seed, mask, k](int start, int end) {
    PRP prp(seed);
    int j = start;
    block tmp[10];
    for(; j < end-4; j+=4) {
      for(int m = 0; m < 10; ++m) {
        tmp[m] = makeBlock(j, m);
      }
      AES_ecb_encrypt_blks(tmp, 10, &prp.aes);
      uint32_t* r = reinterpret_cast<uint32_t*>(tmp);
      for (int m = 0; m < 4; ++m) {
        for (int ix = 0; ix < d; ++ix) {
          int index = (*r) & mask;
          ++r;
          index = index >= k ? index-k : index;
          nn[j+m] = nn[j+m] ^ kk[index];
        }
      }
    }
    for(; j < end; ++j) {
      for(int m = 0; m < 3; ++m) {
        tmp[m] = makeBlock(j, m);
      }
      AES_ecb_encrypt_blks(tmp, 3, &prp.aes);
      uint32_t* r = (uint32_t*)(tmp);
      for (int ix = 0; ix < d; ++ix) {
        nn[j] = nn[j] ^ kk[r[ix]%k];
      }
    }
  };

  vector<std::future<void>> fut;
  int width = n/(threads+1);
  for (int i = 0; i < threads; ++i) {
    int start = i * width;
    int end = min((i+1)* width, n);
    fut.push_back(pool->enqueue([&, start, end]() { task(start, end); }));
  }
  int start = threads * width;
  int end = min((threads+1) * width, n);
  task(start, end);

  for (auto &f: fut) f.get();
}

#endif
