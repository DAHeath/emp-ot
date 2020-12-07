#ifndef MPCOT_REG_H__
#define MPCOT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include "emp-ot/ferret/spcot_sender.h"
#include "emp-ot/ferret/spcot_recver.h"
#include "emp-ot/ferret/preot.h"

using namespace emp;
using std::future;

struct MpDesc {
  std::size_t n;
  std::size_t k;
  std::size_t t;
  std::size_t bin_sz;
};

template<int threads>
class MpcotReg {
public:
  int party;
  int item_n, idx_max, m;
  int tree_height, leave_n;
  int tree_n;
  bool is_malicious;

  NetIO *netio;
  NetIO* ios[threads+1];
  block Delta_f2k;
  block* consist_check_chi_alpha = nullptr;
  block* consist_check_VW = nullptr;

  std::vector<uint32_t> item_pos_recver;

  MpcotReg(bool is_malicious, int party, const MpDesc& desc, NetIO* ios[threads+1])
    : is_malicious(is_malicious)
  {
    this->party = party;
    netio = ios[0];
    for (int i = 0; i < threads+1; ++i)
      this->ios[i] = ios[i];

    this->item_n = desc.t;
    this->idx_max = desc.n;
    this->tree_height = desc.bin_sz+1;
    this->leave_n = 1<<(this->tree_height-1);
    this->tree_n = this->item_n;
  }

  // MPFSS F_2k
  void mpcot(block delta, block * sparse_vector, OTPre<NetIO> * ot, block *pre_cot_data) {
    if(party == BOB) {
      consist_check_chi_alpha = new block[item_n];
    }
    std::vector<block> consist_check_VW(item_n);

    vector<SPCOT_Recver<NetIO>*> recvers;

    if(party == ALICE) {
      Delta_f2k = delta;
      for(int i = 0; i < tree_n; ++i) {
        ot->choices_sender();
      }
      netio->flush();
      ot->reset();
      /* exec_parallel_sender(ot, sparse_vector); */

      { // execute the single-point OTs in parallel
        std::vector<std::thread> ths;
        int width = (this->tree_n+threads)/(threads+1);	
        for(int i = 0; i < threads+1; ++i) {
          int start = i * width;
          int end = min((i+1)*width, tree_n);
          ths.emplace_back(std::thread {
              [this, &consist_check_VW, start, end, width, ot, sparse_vector] {
            for(int i = start; i < end; ++i) {
              spcot_send(tree_height, is_malicious, ot, ios[start/width], i, sparse_vector+i*leave_n, Delta_f2k, consist_check_VW.data()+i);
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
        while(item_set.size() < (size_t)this->item_n) {
          prg.random_data(&rdata, sizeof(uint32_t));
          item_set.insert(rdata%this->idx_max);
        }
        item_pos_recver = std::vector<uint32_t>(item_set.begin(), item_set.end());
      }

      for(int i = 0; i < tree_n; ++i) {
        recvers.push_back(new SPCOT_Recver<NetIO>(netio, tree_height));
        recvers[i]->choice_bit_gen(item_pos_recver[i]%leave_n);
        ot->choices_recver(recvers[i]->b.get());
      }
      netio->flush();
      ot->reset();

      { // execute the single-point OTs in parallel
        std::vector<std::thread> ths;
        int width = (this->tree_n+threads)/(threads+1);
        for (int i = 0; i < threads+1; ++i) {
          int start = i * width;
          int end = min((i+1)*width, tree_n);
          ths.emplace_back(std::thread {
              [this, &consist_check_VW, start, end, width, recvers, ot, sparse_vector] {
            for(int i = start; i < end; ++i) {
              recvers[i]->compute(
                  is_malicious, ot, ios[start/width], i, sparse_vector+i*leave_n, consist_check_chi_alpha+i, consist_check_VW.data()+i);
            }}});
        }

        for (auto& th : ths) { th.join(); }
      }
    }

    if(is_malicious) {
      // consistency check
      GaloisFieldPacking pack;
      if(this->party == ALICE) {
        block r1, r2;
        vector_self_xor(&r1, consist_check_VW.data(), tree_n);
        bool x_prime[128];
        this->netio->recv_data(x_prime, 128*sizeof(bool));
        for(int i = 0; i < 128; ++i) {
          if(x_prime[i])
            pre_cot_data[i] = pre_cot_data[i] ^ this->Delta_f2k;
        }
        pack.packing(&r2, pre_cot_data);
        r1 = r1 ^ r2;
        block dig[2];
        Hash hash;
        hash.hash_once(dig, &r1, sizeof(block));
        this->netio->send_data(dig, 2*sizeof(block));
        this->netio->flush();
      } else {
        block r1, r2, r3;
        vector_self_xor(&r1, consist_check_VW.data(), tree_n);
        vector_self_xor(&r2, this->consist_check_chi_alpha, tree_n);
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
        this->netio->send_data(pre_cot_bool, 128*sizeof(bool));
        this->netio->flush();
        pack.packing(&r3, pre_cot_data);
        r1 = r1 ^ r3;
        block dig[2];
        Hash hash;
        hash.hash_once(dig, &r1, sizeof(block));
        block recv[2];
        this->netio->recv_data(recv, 2*sizeof(block));
        if(!cmpBlock(dig, recv, 2))
          std::cout << "SPCOT consistency check fails" << std::endl;
      }
    }

    for (auto p : recvers) {
      delete p;
    }

    if(party == BOB) {
      delete[] consist_check_chi_alpha;
    }
  }
};
#endif
