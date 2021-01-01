#ifndef EMP_IKNP_H__
#define EMP_IKNP_H__


#include "cot.h"
#include "co.h"
#include "role.h"

#include "gtprg.h"

#include "base.h"

namespace emp {

/**
 * IKNP OT Extension
 * [REF] Implementation of "Extending oblivious transfers efficiently"
 * https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf
 *
 * [REF] With optimization of "More Efficient Oblivious Transfer and Extensions
 * for Faster Secure Computation" https://eprint.iacr.org/2013/552.pdf
 * [REF] With optimization of "Better Concrete Security for Half-Gates Garbling
 * (in the Multi-Instance Setting)" https://eprint.iacr.org/2019/1168.pdf
 **/
namespace IKNP {

static constexpr std::size_t block_size = 1024*2;


inline std::bitset<128> bool_to_bitset(const bool* bs) {
  const block b = bool_to_block(bs);
  std::bitset<128> out;
  memcpy(&out, &b, sizeof(b));
  return out;
}


template <Model model>
void send(NetIO& io, const std::bitset<128>& delta, std::bitset<128> * data, std::size_t n) {
  GT::PRG G[128];
  bool s[128];
  const auto send_block = [&](std::bitset<128>* data, std::size_t len) {
    std::bitset<128> t[block_size];
    std::bitset<128> tmp[block_size];
    std::size_t local_block_size = (len+127)/128*128; // nearest higher multiple of 128
    io.recv_block((block*)tmp, local_block_size);
    for (std::size_t i = 0; i < 128; ++i) {
      for (std::size_t j = 0; j < local_block_size/128; ++j) {
        t[(i*block_size/128) + j] = G[i]();
      }
      if (s[i]) {
        xorBlocks_arr(
            (block*)t+(i*block_size/128),
            (block*)t+(i*block_size/128),
            (block*)tmp+(i*local_block_size/128), local_block_size/128);
      }
    }
    sse_trans((uint8_t *)(data), (uint8_t*)t, 128, block_size);
  };

  std::bitset<128> local_out[block_size];

  NetLink link { &io };
  const auto k0 = BaseOT::recv(link, delta);

  for(std::size_t i = 0; i < 128; ++i) { G[i] = { k0[i] }; }

  std::size_t j = 0;
  for (; j < n/block_size; ++j) {
    send_block(data + j*block_size, block_size);
  }
  std::size_t remain = n % block_size;
  if (remain > 0) {
    send_block(local_out, remain);
    memcpy(data+j*block_size, local_out, sizeof(std::bitset<128>)*remain);
  }

  if constexpr (model == Model::Malicious) {
    // [REF] Implementation of "Actively Secure OT Extension with Optimal
    // Overhead" https://eprint.iacr.org/2015/546.pdf


    send_block(local_out, 256);

    block seed2;
    std::bitset<128> x, t[2], q[2], tmp[2];
    std::bitset<128> chi[block_size];
    q[0] = 0;
    q[1] = 0;
    io.recv_block(&seed2, 1);
    io.flush();

    for(std::size_t i = 0; i < n/block_size; ++i) {
      uni_hash_coeff_gen<block_size>((block*)chi, seed2);
      vector_inn_prdt_sum_no_red<block_size>((block*)tmp, (block*)chi, (block*)data+i*block_size);
      q[0] = q[0] ^ tmp[0];
      q[1] = q[1] ^ tmp[1];
    }
    std::size_t remain = n % block_size;
    if(remain != 0) {
      uni_hash_coeff_gen<block_size>((block*)chi, seed2);
      vector_inn_prdt_sum_no_red((block*)tmp, (block*)chi, (block*)data + n - remain, remain);
      q[0] = q[0] ^ tmp[0];
      q[1] = q[1] ^ tmp[1];
    }
    {
      uni_hash_coeff_gen<256>((block*)chi, seed2);
      vector_inn_prdt_sum_no_red<256>((block*)tmp, (block*)chi, (block*)local_out);
      q[0] = q[0] ^ tmp[0];
      q[1] = q[1] ^ tmp[1];
    }

    io.recv_block((block*)&x, 1);
    io.recv_block((block*)t, 2);


    block x2, delta2;
    memcpy(&x2, &x, sizeof(x));
    memcpy(&delta2, &delta, sizeof(delta));

    mul128(x2, delta2, (block*)tmp, (block*)tmp+1);
    q[0] = q[0] ^ tmp[0];
    q[1] = q[1] ^ tmp[1];

    if (q[0] != t[0] || q[1] != t[1]) {
      error("OT Extension check failed");
    }
  }
}

template <Model model>
void recv(NetIO& io, std::bitset<128>* data, const bool * r, std::size_t n) {
  GT::PRG prg;
  PRG G0[128], G1[128];
  const auto recv_pre_block = [&](std::bitset<128>* data, std::bitset<128>* r, std::size_t len) {
    std::bitset<128> t[block_size];
    std::bitset<128> tmp[block_size];
    std::size_t local_block_size = (len+127)/128 * 128;
    for(std::size_t i = 0; i < 128; ++i) {
      G0[i].random_data(t+(i*block_size/128), local_block_size/8);
      G1[i].random_data(tmp, local_block_size/8);
      xorBlocks_arr((block*)tmp, (block*)t+(i*block_size/128), (block*)tmp, local_block_size/128);
      xorBlocks_arr((block*)tmp, (block*)r, (block*)tmp, local_block_size/128);
      io.send_data((block*)tmp, local_block_size/8);
    }

    sse_trans((uint8_t *)(data), (uint8_t*)t, 128, block_size);
  };

  /* std::bitset<128> k0[128], k1[128]; */
  std::bitset<128> local_out[block_size];

  /* for (std::size_t i = 0; i < 128; ++i) { */
  /*   k0[i] = prg(); */
  /*   k1[i] = prg(); */
  /* } */

  NetLink link { &io };
  const auto [k0, k1] = BaseOT::send(link);
  /* OTCO<NetIO>(&io).send((block*)k0, (block*)k1, 128); */

  for (std::size_t i = 0; i < 128; ++i) {
    G0[i].reseed((block*)&k0[i]);
    G1[i].reseed((block*)&k1[i]);
  }

  std::vector<std::bitset<128>> block_r ((n+127)/128);
  for(std::size_t i = 0; i < (n+127)/128; ++i) {
    block_r[i] = bool_to_bitset(r+i*128);
  }

  std::size_t j = 0;
  for (; j < n/block_size; ++j) {
    recv_pre_block(data+j*block_size, block_r.data() + (j*block_size/128), block_size);
  }
  std::size_t remain = n % block_size;
  if (remain > 0) {
    recv_pre_block(local_out, block_r.data() + (j*block_size/128), remain);
    memcpy(data+j*block_size, local_out, sizeof(std::bitset<128>)*remain);
  }


  if (model == Model::Malicious) {
    bool local_r[256];
    std::bitset<128> local_r_block[2];
    prg.random_bool(local_r, 256);
    local_r_block[0] = bool_to_bitset(local_r);
    local_r_block[1] = bool_to_bitset(local_r + 128);
    recv_pre_block(local_out, local_r_block, 256);


    std::bitset<128> select[2];
    select[0] = std::bitset<128> { 0 };
    select[1] = std::bitset<128> { 0 }.flip();

    std::bitset<128> x = 0;
    std::bitset<128> t[2], tmp[2];
    const auto seed2 = prg();
    io.send_block((block*)&seed2, 1);
    io.flush();
    std::bitset<128> chi[block_size];
    t[0] = 0;
    t[1] = 0;

    block seed2_;
    memcpy(&seed2_, &seed2, sizeof(seed2));

    for (std::size_t i = 0; i < n/block_size; ++i) {
      uni_hash_coeff_gen<block_size>((block*)chi, seed2_);
      vector_inn_prdt_sum_no_red<block_size>((block*)tmp, (block*)chi, (block*)data+i*block_size);
      t[0] ^= tmp[0];
      t[1] ^= tmp[1];
      for(std::size_t j = 0; j < block_size; ++j) 
        x ^= (chi[j] & select[r[i*block_size+j]]);
    }

    std::size_t remain = n % block_size;
    if (remain != 0) {
      uni_hash_coeff_gen<block_size>((block*)chi, seed2_);
      vector_inn_prdt_sum_no_red((block*)tmp, (block*)chi, (block*)data+n - remain, remain);
      t[0] ^= tmp[0];
      t[1] ^= tmp[1];
      for(std::size_t j = 0; j < remain; ++j) {
        x ^= (chi[j] & select[r[n - remain + j]]);
      }
    }

    uni_hash_coeff_gen<256>((block*)chi, seed2_);
    vector_inn_prdt_sum_no_red<256>((block*)tmp, (block*)chi, (block*)local_out);
    t[0] ^= tmp[0];
    t[1] ^= tmp[1];
    for(std::size_t j = 0; j < 256; ++j) {
      x ^= (chi[j] & select[local_r[j]]);
    }

    io.send_block((block*)&x, 1);
    io.send_block((block*)t, 2);
  }
}

}

}
#endif
