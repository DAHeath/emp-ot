#ifndef LPN_ERROR_H__
#define LPN_ERROR_H__

#include <emp-tool/emp-tool.h>
#include "emp-ot/role.h"
#include "emp-ot/ferret/gtprg.h"

#include <unordered_set>
#include <span>

namespace emp {


// distributed point function


void ggm_expand(
    const std::bitset<128>& parent,
    std::bitset<128>& child0,
    std::bitset<128>& child1) {
  static GT::PRP f0(0);
  static GT::PRP f1(1);
  child0 = f0(parent);
  child1 = f1(parent);

  child0[0] = 0;
  child1[0] = 0;
}


namespace DPF {

std::vector<std::pair<std::bitset<128>, std::bitset<128>>>
send(
    std::size_t depth,
    std::bitset<128> seed,
    std::span<std::bitset<128>> tar) {
  std::vector<std::pair<std::bitset<128>, std::bitset<128>>> out(depth);

  tar[0] = seed;
  for (std::size_t h = 0; h < depth-1; ++h) {
    out[h].first = 0;
    out[h].second = 0;
    for (int i = (1 << h)-1; i >= 0; --i) {
      ggm_expand(tar[i], tar[i*2], tar[i*2+1]);
      out[h].first ^= tar[i*2];
      out[h].second ^= tar[i*2+1];
    }
  }

  return out;
}


void recv(
    std::size_t depth,
    std::span<const bool> choices,
    std::span<const std::bitset<128>> stacks,
    std::span<std::bitset<128>> tar) {
  std::size_t ptr = 0;
  for (std::size_t i = 0; i < depth-1; ++i) {
    // reconstruct a layer of the ggm tree
    tar[ptr] = tar[ptr+1] = 0;
    std::size_t item_n = 1<< (i+1);

    std::bitset<128> sum = 0;
    for (std::size_t j = choices[i]; j < item_n; j+=2) {
      sum ^= tar[j];
    }

    tar[ptr + choices[i]] = sum ^ stacks[i];
    if (i+1 < depth-1) {
      for (int j = item_n-1; j >= 0; --j) {
        ggm_expand(tar[j], tar[j*2], tar[j*2+1]);
      }
    }
    ptr = (ptr + !choices[i]) * 2;
  }
}

}




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
std::vector<std::uint32_t> range_subset(GT::PRG& prg, std::uint32_t cap, std::size_t n) {
  std::uint32_t xs[4];
  std::unordered_set<std::uint32_t> s;
  while (s.size() < n) {
    // prg produces 128 bits per call, so fill four words at once
    std::bitset<128> r = prg();
    memcpy(xs, &r, 16);
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
    const MpDesc& desc,
    NetIO* io,
    GT::PRG& prg,
    std::bitset<128> delta,
    std::bitset<128> * sparse_vector,
    std::span<std::bitset<128>> pre_cot_data) {
  auto tree_height = desc.bin_sz+1;
  std::size_t leave_n = 1<<(tree_height-1);

  std::unique_ptr<bool[]> bs(new bool[(tree_height-1)*desc.t]);
  std::vector<std::uint32_t> positions;
  // make single point ot choices
  if constexpr (role == Role::Receiver) {
    positions = range_subset(prg, desc.n, desc.t);

    bs = std::unique_ptr<bool[]>(new bool[(tree_height-1)*desc.t]);

    auto choice_bits = [&](int choice, bool* out) {
      for (int i = tree_height-2; i >= 0; --i) {
        out[i] = (choice & 1) == 0;
        choice >>= 1;
      }
    };

    for (std::size_t i = 0; i < desc.t; ++i) {
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
      for (std::size_t i = 0; i < n; ++i) {
        bits[i] = (bs[i] != pre_cot_data[i][0]);
      }
      io->send_data(bits.get(), n);
    }
  }
  io->flush();

  std::size_t width = (desc.t+threads)/(threads+1);
  std::vector<std::bitset<128>> pad(2 * desc.t * desc.bin_sz);
  std::vector<std::bitset<128>> secret_sums_f2(desc.t);

  if (role == Role::Receiver) {
    io->recv_block((block*)pad.data(), pad.size());
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
      for (std::size_t j = start; j < end; ++j) {
        auto subvector = std::span { sparse_vector + j*leave_n, leave_n };
        std::size_t k = j*desc.bin_sz;

        if constexpr (role == Role::Sender) {
          const auto messages = DPF::send(tree_height, prg(), subvector);

          secret_sums_f2[j] = delta;
          for (std::size_t i = 0; i < leave_n; ++i) {
            secret_sums_f2[j] ^= subvector[i];
          }

          for (std::size_t i = 0; i < desc.bin_sz; ++i) {
            pad[2*(j*desc.bin_sz + i)] = messages[i].first ^ pre_data[k+i + bits[k+i]*n];
            pad[2*(j*desc.bin_sz + i)+1] = messages[i].second ^ pre_data[k+i + (!bits[k+i])*n];
          }

          if (model == Model::Malicious) {
            // consistency check
            std::vector<std::bitset<128>> chi(leave_n);
            Hash hash;
            block digest[2];
            hash.hash_once(digest, &secret_sums_f2[j], sizeof(block));
            uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);

            vector_inn_prdt_sum_red((block*)&consist_check_VW[j], (block*)chi.data(), (block*)subvector.data(), leave_n);
          }
        } else {
          std::vector<std::bitset<128>> m(tree_height-1);

          auto b = bs.get() + j*(tree_height-1);
          std::size_t k = j*desc.bin_sz;

          for (std::size_t i = 0; i < desc.bin_sz; ++i) {
            m[i] = pre_data[k+i] ^ pad[2*(j*desc.bin_sz + i) + b[i]];
          }

          DPF::recv(tree_height, std::span<const bool> { b, tree_height-1 }, m, subvector);

          std::size_t choice_pos = positions[j]%leave_n;
          std::bitset<128> sum = 0;
          for (std::size_t i = 0; i < leave_n; ++i) { sum ^= subvector[i]; }
          subvector[choice_pos] ^= sum ^ secret_sums_f2[j];

          if (model == Model::Malicious) {
            // check consistency
            std::vector<std::bitset<128>> chi(leave_n);
            Hash hash;
            block digest[2];
            hash.hash_once(digest, &secret_sums_f2[j], sizeof(block));
            uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);
            auto chi_alpha = chi[choice_pos];
            std::bitset<128> W;
            vector_inn_prdt_sum_red((block*)&W, (block*)chi.data(), (block*)subvector.data(), leave_n);

            consist_check_chi_alpha[j] = chi_alpha;
            consist_check_VW[j] = W;
          }
        }
      }}});
  }
  for (auto& th : ths) { th.join(); }

  if constexpr (role == Role::Sender) {
    io->send_block((block*)pad.data(), pad.size());
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
      for(std::size_t i = 0; i < 128; ++i) {
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
      for (std::size_t i = 0; i < 2; ++i) {
        for (std::size_t j = 0; j < 64; ++j) {
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
