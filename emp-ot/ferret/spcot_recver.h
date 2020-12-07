#ifndef SPCOT_RECVER_H__
#define SPCOT_RECVER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/twokeyprp.h"

using namespace emp;

template<typename IO>
class SPCOT_Recver {
public:
  IO *io;
  block* ggm_tree;
  int choice_pos, depth, leave_n;
  std::vector<block> m;
  std::unique_ptr<bool[]> b;

  block secret_sum_f2;

  SPCOT_Recver(IO *io, int depth)
    : io(io), depth(depth), leave_n(1 << (depth-1)), m(depth-1), b(new bool[depth-1]) { }

  // generate the choice bit of blivious transfer
  void choice_bit_gen(int choice_loc) {
    /* std::unique_ptr<bool[]> b(new bool[depth-1]); */
    choice_pos = choice_loc;
    int leaves_n = 1<<(depth-1);
    if(choice_pos > leaves_n) {
      std::cout << "index exceeds the limit" << std::endl;
      exit(0);
    }

    int idx = choice_loc--;
    for(int i = depth-2; i >= 0; --i) {
      b[i] = (idx % 2) == 0;
      idx >>= 1;
    }
    /* return b; */
  }

  // receive the message and reconstruct the tree
  // j: position of the secret, begins from 0
  template <typename OT>
  void compute(bool malicious, OT * ot, NetIO * io2, int s, block* ggm_tree_mem, block *chi_alpha, block *W) {
    ot->recv(m.data(), b.get(), depth-1, io2, s);
    io2->recv_data(&secret_sum_f2, sizeof(block));

    this->ggm_tree = ggm_tree_mem;

    { // gmm tree reconstruction
      int to_fill_idx = 0;
      TwoKeyPRP prp(zero_block, makeBlock(0, 1));
      for (int i = 0; i < depth-1; ++i) {
        to_fill_idx = to_fill_idx * 2;
        ggm_tree[to_fill_idx] = ggm_tree[to_fill_idx+1] = zero_block;

        { // reconstruct a layer of the ggm tree
          int item_n = 1<< (i+1);
          block nodes_sum = zero_block;

          for (int j = b[i] != 0; j < item_n; j+=2) {
            nodes_sum = nodes_sum ^ ggm_tree[j];
          }
          ggm_tree[to_fill_idx + b[i]] = nodes_sum ^ m[i];
          if(i+1 != this->depth-1) {
            for (int j = item_n-2; j >= 0; j-=2) {
              prp.node_expand_2to4(&ggm_tree[j*2], &ggm_tree[j]);
            }
          }
        }

        to_fill_idx += !b[i];
      }
    }

    ggm_tree[choice_pos] = zero_block;
    block nodes_sum = zero_block;
    block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
    for(int i = 0; i < leave_n; ++i) {
      ggm_tree[i] = ggm_tree[i] & one;
      nodes_sum = nodes_sum ^ ggm_tree[i];
    }
    ggm_tree[choice_pos] = nodes_sum ^ secret_sum_f2;

    if (malicious) {
      // check consistency
      std::vector<block> chi(leave_n);
      Hash hash;
      block digest[2];
      hash.hash_once(digest, &secret_sum_f2, sizeof(block));
      uni_hash_coeff_gen(chi.data(), digest[0], leave_n);
      *chi_alpha = chi[choice_pos];
      vector_inn_prdt_sum_red(W, chi.data(), ggm_tree, leave_n);
    }
  }
};
#endif
