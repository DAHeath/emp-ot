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
    std::bitset<128> delta,
    std::bitset<128> * sparse_vector,
    std::span<std::bitset<128>> pre_cot_data) {
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

  std::vector<std::bitset<128>> pre_data(2*n);
  std::unique_ptr<bool[]> bits(new bool[n]);
  { // pre OT
    CCRH ccrh;
    if constexpr (role == Role::Sender) {
      ccrh.Hn((block*)pre_data.data(), (block*)pre_cot_data.data(), 0, n, (block*)pre_data.data()+n);
      xorBlocks_arr((block*)pre_data.data()+n, (block*)pre_cot_data.data(), *(block*)&delta, n);
      ccrh.Hn((block*)pre_data.data()+n, (block*)pre_data.data()+n, 0, n);
      io->recv_data(bits.get(), n);
    } else {
      ccrh.Hn((block*)pre_data.data(), (block*)pre_cot_data.data(), 0, n);
      for (int i = 0; i < n; ++i) {
        bits[i] = (bs[i] != pre_cot_data[i][0]);
      }
      io->send_data(bits.get(), n);
    }
  }
  io->flush();

  int width = (desc.t+threads)/(threads+1);
  std::vector<std::bitset<128>> blocks(2 * desc.t * desc.bin_sz);
  std::vector<std::bitset<128>> secret_sums_f2(desc.t);


  if (role == Role::Receiver) {
    io->recv_block((block*)blocks.data(), blocks.size());
    io->recv_block((block*)secret_sums_f2.data(), secret_sums_f2.size());
  }

  std::vector<std::bitset<128>> consist_check_chi_alpha;
  if constexpr (role == Role::Receiver) {
    consist_check_chi_alpha = std::vector<std::bitset<128>>(desc.t);
  }
  std::vector<std::bitset<128>> consist_check_VW(desc.t);

  // execute the single-point OTs in parallel
  std::vector<std::thread> ths;
  for (std::size_t i = 0; i < threads+1; ++i) {
    std::size_t start = i * width;
    std::size_t end = std::min((std::size_t)(i+1)*width, desc.t);
    ths.emplace_back(std::thread { [&, start, end] {
      GT::PRG prg;
      for (std::size_t j = start; j < end; ++j) {
        std::bitset<128>* ggm_tree = sparse_vector+j*leave_n;
        std::span<std::bitset<128>> pad = blocks;
        pad = pad.subspan(j * 2*desc.bin_sz, 2*desc.bin_sz);

        if constexpr (role == Role::Sender) {
          std::bitset<128> seed = prg();
          std::vector<std::bitset<128>> m((tree_height-1) * 2);

          // generate GGM tree from the top
          {
            auto ot_msg_0 = m.data();
            auto ot_msg_1 = m.data() + tree_height - 1;
            ggm_expand(seed, ggm_tree[0], ggm_tree[1]);
            ot_msg_0[0] = ggm_tree[0];
            ot_msg_1[0] = ggm_tree[1];
            for (std::size_t h = 1; h < tree_height-1; ++h) {
              ot_msg_0[h] = ot_msg_1[h] = 0;
              std::size_t sz = 1<<h;
              for (int i = sz-1; i >= 0; --i) {
                ggm_expand(ggm_tree[i], ggm_tree[i*2], ggm_tree[i*2+1]);
                ot_msg_0[h] ^= ggm_tree[i*2];
                ot_msg_1[h] ^= ggm_tree[i*2+1];
              }
            }
          }

          secret_sums_f2[j] = delta;
          std::bitset<128> one = (std::bitset<128> { 1 }).flip();
          for (std::size_t i = 0; i < leave_n; ++i) {
            ggm_tree[i] &= one;
            secret_sums_f2[j] ^= ggm_tree[i];
          }

          if (model == Model::Malicious) {
            // consistency check
            std::vector<std::bitset<128>> chi(leave_n);
            Hash hash;
            block digest[2];
            hash.hash_once(digest, &secret_sums_f2[j], sizeof(block));
            uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);

            vector_inn_prdt_sum_red((block*)&consist_check_VW[j], (block*)chi.data(), (block*)ggm_tree, leave_n);
          }

          auto m0 = m.data();
          auto m1 = &m[tree_height-1];

          int k = j*desc.bin_sz;
          for (int i = 0; i < desc.bin_sz; ++i) {
            pad[2*i] = m0[i] ^ pre_data[k+i + bits[k+i]*n];
            pad[2*i+1] = m1[i] ^ pre_data[k+i + (!bits[k+i])*n];
          }
        } else {
          std::vector<std::bitset<128>> m(tree_height-1);

          auto b = bs.get() + j*(tree_height-1);
          int k = j*desc.bin_sz;

          for (int i = 0; i < desc.bin_sz; ++i) {
            m[i] = pre_data[k+i] ^ pad[2*i + b[i]];
          }

          { // gmm tree reconstruction
            int to_fill_idx = 0;
            for (int i = 0; i < tree_height-1; ++i) {
              // reconstruct a layer of the ggm tree
              to_fill_idx = to_fill_idx * 2;
              ggm_tree[to_fill_idx] = ggm_tree[to_fill_idx+1] = 0;
              int item_n = 1<< (i+1);

              std::bitset<128> nodes_sum = 0;
              for (std::size_t j = b[i] != 0; j < item_n; j+=2) {
                nodes_sum ^= ggm_tree[j];
              }

              ggm_tree[to_fill_idx + b[i]] = nodes_sum ^ m[i];
              if (i+1 != tree_height-1) {
                for (int j = item_n-1; j >= 0; --j) {
                  ggm_expand(ggm_tree[j], ggm_tree[j*2], ggm_tree[j*2+1]);
                }
              }
              to_fill_idx += !b[i];
            }
          }

          int choice_pos = positions[j]%leave_n;
          ggm_tree[choice_pos] = 0;
          std::bitset<128> one = (std::bitset<128> { 1 }).flip();
          std::bitset<128> nodes_sum = 0;
          for(int i = 0; i < leave_n; ++i) {
            ggm_tree[i] &= one;
            nodes_sum ^= ggm_tree[i];
          }
          ggm_tree[choice_pos] = nodes_sum ^ secret_sums_f2[j];

          if (model == Model::Malicious) {
            // check consistency
            std::vector<std::bitset<128>> chi(leave_n);
            Hash hash;
            block digest[2];
            hash.hash_once(digest, &secret_sums_f2[j], sizeof(block));
            uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);
            auto chi_alpha = chi[choice_pos];
            std::bitset<128> W;
            vector_inn_prdt_sum_red((block*)&W, (block*)chi.data(), (block*)ggm_tree, leave_n);

            consist_check_chi_alpha[j] = chi_alpha;
            consist_check_VW[j] = W;
          }
        }
      }}});
  }
  for (auto& th : ths) { th.join(); }

  if constexpr (role == Role::Sender) {
    io->send_block((block*)blocks.data(), blocks.size());
    io->send_block((block*)secret_sums_f2.data(), secret_sums_f2.size());
    io->flush();
  }

  if (model == Model::Malicious) {
    // consistency check
    GaloisFieldPacking pack;
    if constexpr (role == Role::Sender) {
      block r1, r2;
      vector_self_xor(&r1, (block*)consist_check_VW.data(), desc.t);
      bool x_prime[128];
      io->recv_data(x_prime, 128*sizeof(bool));
      for(int i = 0; i < 128; ++i) {
        if(x_prime[i])
          pre_cot_data[i] = pre_cot_data[i] ^ delta;
      }
      pack.packing(&r2, (block*)pre_cot_data.data());
      r1 = r1 ^ r2;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      io->send_data(dig, 2*sizeof(block));
      io->flush();
    } else {
      block r1, r2, r3;
      vector_self_xor(&r1, (block*)consist_check_VW.data(), desc.t);
      vector_self_xor(&r2, (block*)consist_check_chi_alpha.data(), desc.t);
      uint64_t pos[2];
      pos[0] = _mm_extract_epi64(r2, 0);
      pos[1] = _mm_extract_epi64(r2, 1);
      bool pre_cot_bool[128];
      for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 64; ++j) {
          pre_cot_bool[i*64+j] = ((pos[i] & 1) == 1) ^ pre_cot_data[i*64+j][0];
          pos[i] >>= 1;
        }
      }
      io->send_data(pre_cot_bool, 128*sizeof(bool));
      io->flush();
      pack.packing(&r3, (block*)pre_cot_data.data());
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
