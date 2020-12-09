#ifndef MPCOT_REG_H__
#define MPCOT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include <unordered_set>
#include "emp-ot/ferret/spcot.h"
#include "emp-ot/ferret/preot.h"
#include "emp-ot/ferret/role.h"

namespace emp {

static constexpr std::size_t CONSIST_CHECK_COT_NUM = 128;

struct MpDesc {
  std::size_t n;
  std::size_t k;
  std::size_t t;
  std::size_t bin_sz;
  std::size_t m;
  std::size_t mask;
  std::size_t limit;
};


// Select a random size n subset of the range [0..cap)
std::vector<std::uint32_t> range_subset(std::uint32_t cap, std::size_t n) {
  PRG prg;
  std::uint32_t xs[4];
  std::unordered_set<std::uint32_t> s;
  while (s.size() < n) {
    // prg produces 128 bits per call, so fill four words at once
    prg.random_data(xs, sizeof(std::uint32_t)*4);
    s.insert(xs[0] % cap);
    s.insert(xs[1] % cap);
    s.insert(xs[2] % cap);
    s.insert(xs[3] % cap);
  }
  while (s.size() > n) {
    // we might overfill, so trim back to desired size (max overshoot is only three).
    s.erase(s.begin());
  }
  return std::vector<std::uint32_t>(s.begin(), s.end());
}


// MPFSS F_2k
template<Role role, std::size_t threads>
void mpcot(
  bool is_malicious, const MpDesc& desc, NetIO* ios[threads+1],
    block delta,
    block * sparse_vector,
    std::span<block> pre_cot_data) {
  auto netio = ios[0];
  auto tree_height = desc.bin_sz+1;
  int leave_n = 1<<(tree_height-1);

  std::vector<block> consist_check_chi_alpha;;
  if constexpr(role == Role::Receiver) {
    consist_check_chi_alpha = std::vector<block>(desc.t);
  }
  std::vector<block> consist_check_VW(desc.t);


  std::unique_ptr<bool[]> bs(new bool[(tree_height-1)*desc.t]);
  std::vector<std::uint32_t> positions;
  // make single point ot choices
  if constexpr (role == Role::Receiver) {
    positions = range_subset(desc.n, desc.t);

    bs = std::unique_ptr<bool[]>(new bool[(tree_height-1)*desc.t]);

    auto choice_bits = [&](int choice, bool* out) {
      for (int i = tree_height-2; i >= 0; --i) {
        out[i] = (choice & 1) == 0;
        choice >>= 1;
      }
    };

    for (int i = 0; i < desc.t; ++i) {
      choice_bits(positions[i] % leave_n, bs.get() + i*(tree_height-1));
    }
  }

  OTPre<role> ot(desc.bin_sz * desc.t);
  ot.pre(pre_cot_data, delta);
  ot.choose(netio, bs.get(), (tree_height-1)*desc.t);
  netio->flush();

  // execute the single-point OTs in parallel
  std::vector<std::thread> ths;
  int width = (desc.t+threads)/(threads+1);	
  for(int i = 0; i < threads+1; ++i) {
    int start = i * width;
    int end = std::min((std::size_t)(i+1)*width, desc.t);
    ths.emplace_back(std::thread { [&, start, end] {
      for(int j = start; j < end; ++j) {
        if constexpr (role == Role::Sender) {
          auto [secret_sum_f2, m] = spcot_send(
              tree_height,
              is_malicious,
              sparse_vector+j*leave_n,
              delta,
              consist_check_VW.data()+j);
          auto io = ios[start/width];
          ot.send(m.data(), &m[tree_height-1], tree_height-1, io, j);
          io->send_data(&secret_sum_f2, sizeof(block));
          io->flush();
        } else {
          auto io = ios[start/width];
          std::vector<block> m(tree_height-1);
          ot.recv(m.data(), bs.get() + j*(tree_height-1), tree_height-1, io, j);
          block secret_sum_f2;
          io->recv_data(&secret_sum_f2, sizeof(block));

          spcot_recv(
              m,
              secret_sum_f2,
              tree_height,
              positions[j]%leave_n,
              bs.get() + j*(tree_height-1),
              is_malicious,
              sparse_vector+j*leave_n,
              consist_check_chi_alpha.data()+j,
              consist_check_VW.data()+j);
        }
      }}});
  }
  for (auto& th : ths) { th.join(); }

  if (is_malicious) {
    // consistency check
    GaloisFieldPacking pack;
    if constexpr (role == Role::Sender) {
      block r1, r2;
      vector_self_xor(&r1, consist_check_VW.data(), desc.t);
      bool x_prime[128];
      netio->recv_data(x_prime, 128*sizeof(bool));
      for(int i = 0; i < 128; ++i) {
        if(x_prime[i])
          pre_cot_data[i] = pre_cot_data[i] ^ delta;
      }
      pack.packing(&r2, pre_cot_data.data());
      r1 = r1 ^ r2;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      netio->send_data(dig, 2*sizeof(block));
      netio->flush();
    } else {
      block r1, r2, r3;
      vector_self_xor(&r1, consist_check_VW.data(), desc.t);
      vector_self_xor(&r2, consist_check_chi_alpha.data(), desc.t);
      uint64_t pos[2];
      pos[0] = _mm_extract_epi64(r2, 0);
      pos[1] = _mm_extract_epi64(r2, 1);
      bool pre_cot_bool[128];
      for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 64; ++j) {
          pre_cot_bool[i*64+j] = ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i*64+j]);
          pos[i] >>= 1;
        }
      }
      netio->send_data(pre_cot_bool, 128*sizeof(bool));
      netio->flush();
      pack.packing(&r3, pre_cot_data.data());
      r1 = r1 ^ r3;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      block recv[2];
      netio->recv_data(recv, 2*sizeof(block));
      if (!cmpBlock(dig, recv, 2)) {
        std::cout << "SPCOT consistency check fails" << std::endl;
      }
    }
  }
}

}

#endif
