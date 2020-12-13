#ifndef LPN_ERROR_H__
#define LPN_ERROR_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include <unordered_set>
#include "emp-ot/ferret/lpn_error_point.h"
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
template<Model model, Role role, std::size_t threads>
void lpn_error(
  const MpDesc& desc, NetIO* io,
    block delta,
    block * sparse_vector,
    std::span<block> pre_cot_data) {
  auto tree_height = desc.bin_sz+1;
  int leave_n = 1<<(tree_height-1);

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

  auto n = desc.bin_sz * desc.t;

  std::vector<block> pre_data(2*n);
  std::unique_ptr<bool[]> bits(new bool[n]);
  { // pre OT
    CCRH ccrh;
    if constexpr (role == Role::Sender) {
      ccrh.Hn(pre_data.data(), pre_cot_data.data(), 0, n, pre_data.data()+n);
      xorBlocks_arr(pre_data.data()+n, pre_cot_data.data(), delta, n);
      ccrh.Hn(pre_data.data()+n, pre_data.data()+n, 0, n);
      io->recv_data(bits.get(), n);
    } else {
      ccrh.Hn(pre_data.data(), pre_cot_data.data(), 0, n);
      for (int i = 0; i < n; ++i) {
        bits[i] = (bs[i] != getLSB(pre_cot_data[i]));
      }
      io->send_data(bits.get(), n);
    }
  }
  io->flush();

  int width = (desc.t+threads)/(threads+1);
  std::vector<block> blocks(2 * desc.t * desc.bin_sz);
  std::vector<block> secret_sums_f2(desc.t);


  if (role == Role::Receiver) {
    io->recv_block(blocks.data(), blocks.size());
    io->recv_block(secret_sums_f2.data(), secret_sums_f2.size());
  }

  std::vector<block> consist_check_chi_alpha;
  if constexpr (role == Role::Receiver) {
    consist_check_chi_alpha = std::vector<block>(desc.t);
  }
  std::vector<block> consist_check_VW(desc.t);

  // execute the single-point OTs in parallel
  std::vector<std::thread> ths;
  for(int i = 0; i < threads+1; ++i) {
    int start = i * width;
    int end = std::min((std::size_t)(i+1)*width, desc.t);
    ths.emplace_back(std::thread { [&, start, end] {
      for (int j = start; j < end; ++j) {
        std::span<block> pad = blocks;
        pad = pad.subspan(j * 2*desc.bin_sz, 2*desc.bin_sz);

        if constexpr (role == Role::Sender) {
          auto [secret_sum_f2, m] = error_point_send<model>(
              tree_height,
              sparse_vector+j*leave_n,
              delta,
              consist_check_VW.data()+j);
          secret_sums_f2[j] = secret_sum_f2;

          auto m0 = m.data();
          auto m1 = &m[tree_height-1];

          int k = j*desc.bin_sz;
          for (int i = 0; i < desc.bin_sz; ++i) {
            pad[2*i] = m0[i] ^ pre_data[k+i + bits[k+i]*n];
            pad[2*i+1] = m1[i] ^ pre_data[k+i + (!bits[k+i])*n];
          }
        } else {
          std::vector<block> m(tree_height-1);

          auto b = bs.get() + j*(tree_height-1);
          int k = j*desc.bin_sz;

          for (int i = 0; i < desc.bin_sz; ++i) {
            m[i] = pre_data[k+i] ^ pad[2*i + b[i]];
          }

          error_point_recv<model>(
              m,
              secret_sums_f2[j],
              tree_height,
              positions[j]%leave_n,
              bs.get() + j*(tree_height-1),
              sparse_vector+j*leave_n,
              consist_check_chi_alpha.data()+j,
              consist_check_VW.data()+j);
        }
      }}});
  }
  for (auto& th : ths) { th.join(); }

  if constexpr (role == Role::Sender) {
    io->send_block(blocks.data(), blocks.size());
    io->send_block(secret_sums_f2.data(), secret_sums_f2.size());
    io->flush();
  }

  if (model == Model::Malicious) {
    // consistency check
    GaloisFieldPacking pack;
    if constexpr (role == Role::Sender) {
      block r1, r2;
      vector_self_xor(&r1, consist_check_VW.data(), desc.t);
      bool x_prime[128];
      io->recv_data(x_prime, 128*sizeof(bool));
      for(int i = 0; i < 128; ++i) {
        if(x_prime[i])
          pre_cot_data[i] = pre_cot_data[i] ^ delta;
      }
      pack.packing(&r2, pre_cot_data.data());
      r1 = r1 ^ r2;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      io->send_data(dig, 2*sizeof(block));
      io->flush();
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
      io->send_data(pre_cot_bool, 128*sizeof(bool));
      io->flush();
      pack.packing(&r3, pre_cot_data.data());
      r1 = r1 ^ r3;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      block recv[2];
      io->recv_data(recv, 2*sizeof(block));
      if (!cmpBlock(dig, recv, 2)) {
        std::cout << "SPCOT consistency check fails" << std::endl;
      }
    }
  }
}

}

#endif
