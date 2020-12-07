#ifndef MPCOT_REG_H__
#define MPCOT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include "emp-ot/ferret/spcot.h"
#include "emp-ot/ferret/preot.h"
#include "emp-ot/ferret/role.h"

namespace emp {

struct MpDesc {
  std::size_t n;
  std::size_t k;
  std::size_t t;
  std::size_t bin_sz;
};


// MPFSS F_2k
template<Role role, std::size_t threads>
void mpcot(
  bool is_malicious, const MpDesc& desc, NetIO* ios[threads+1],
    block delta, block * sparse_vector, OTPre<NetIO> * ot, block *pre_cot_data) {
  auto netio = ios[0];
  auto item_n = desc.t;
  auto idx_max = desc.n;
  auto tree_height = desc.bin_sz+1;
  int leave_n = 1<<(tree_height-1);
  int tree_n = item_n;
  std::vector<uint32_t> item_pos_recver;



  block* consist_check_chi_alpha = nullptr;
  if constexpr(role == Role::Receiver) {
    consist_check_chi_alpha = new block[item_n];
  }
  std::vector<block> consist_check_VW(item_n);

  if constexpr (role == Role::Sender) {
    for(int i = 0; i < tree_n; ++i) {
      ot->choices_sender();
    }
    netio->flush();
    ot->reset();
    /* exec_parallel_sender(ot, sparse_vector); */

    { // execute the single-point OTs in parallel
      std::vector<std::thread> ths;
      int width = (tree_n+threads)/(threads+1);	
      for(int i = 0; i < threads+1; ++i) {
        int start = i * width;
        int end = std::min((i+1)*width, tree_n);
        ths.emplace_back(std::thread {
            [leave_n, ios, is_malicious, tree_height, delta, &consist_check_VW, start, end, width, ot, sparse_vector] {
          for(int i = start; i < end; ++i) {
            spcot_send(tree_height, is_malicious, ot, ios[start/width], i, sparse_vector+i*leave_n, delta, consist_check_VW.data()+i);
          }}});
      }
      for (auto& th : ths) { th.join(); }
    }

  } else {
    { // init
      PRG prg;
      std::set<uint32_t> item_set;
      uint32_t rdata;
      item_set.clear();
      while(item_set.size() < (size_t)item_n) {
        prg.random_data(&rdata, sizeof(uint32_t));
        item_set.insert(rdata%idx_max);
      }
      item_pos_recver = std::vector<uint32_t>(item_set.begin(), item_set.end());
    }

    std::vector<std::unique_ptr<bool[]>> bs;
    for(int i = 0; i < desc.t; ++i) {
      bs.emplace_back(choice_bit_gen(tree_height, item_pos_recver[i]%leave_n));
      ot->choices_recver(bs.back().get());
    }
    netio->flush();
    ot->reset();

    { // execute the single-point OTs in parallel
      std::vector<std::thread> ths;
      int width = (tree_n+threads)/(threads+1);
      for (int i = 0; i < threads+1; ++i) {
        int start = i * width;
        int end = min((i+1)*width, tree_n);
        ths.emplace_back(std::thread {
            [&, start, end] {
          for(int j = start; j < end; ++j) {
            spcot_recv(
                tree_height,
                item_pos_recver[j]%leave_n,
                bs[j].get(),
                is_malicious, ot, ios[start/width], j, sparse_vector+j*leave_n, consist_check_chi_alpha+j, consist_check_VW.data()+j);
          }}});
      }

      for (auto& th : ths) { th.join(); }
    }
  }

  if (is_malicious) {
    // consistency check
    GaloisFieldPacking pack;
    if constexpr (role == Role::Sender) {
      block r1, r2;
      vector_self_xor(&r1, consist_check_VW.data(), tree_n);
      bool x_prime[128];
      netio->recv_data(x_prime, 128*sizeof(bool));
      for(int i = 0; i < 128; ++i) {
        if(x_prime[i])
          pre_cot_data[i] = pre_cot_data[i] ^ delta;
      }
      pack.packing(&r2, pre_cot_data);
      r1 = r1 ^ r2;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      netio->send_data(dig, 2*sizeof(block));
      netio->flush();
    } else {
      block r1, r2, r3;
      vector_self_xor(&r1, consist_check_VW.data(), tree_n);
      vector_self_xor(&r2, consist_check_chi_alpha, tree_n);
      uint64_t pos[2];
      pos[0] = _mm_extract_epi64(r2, 0);
      pos[1] = _mm_extract_epi64(r2, 1);
      bool pre_cot_bool[128];
      for(int i = 0; i < 2; ++i) {
        for(int j = 0; j < 64; ++j) {
          pre_cot_bool[i*64+j] = ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i*64+j]);
          pos[i] >>= 1;
        }
      }
      netio->send_data(pre_cot_bool, 128*sizeof(bool));
      netio->flush();
      pack.packing(&r3, pre_cot_data);
      r1 = r1 ^ r3;
      block dig[2];
      Hash hash;
      hash.hash_once(dig, &r1, sizeof(block));
      block recv[2];
      netio->recv_data(recv, 2*sizeof(block));
      if(!cmpBlock(dig, recv, 2))
        std::cout << "SPCOT consistency check fails" << std::endl;
    }
  }

  if (role == Role::Receiver) {
    delete[] consist_check_chi_alpha;
  }
}

}

#endif
