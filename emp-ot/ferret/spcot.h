#ifndef SPCOT_RECVER_H__
#define SPCOT_RECVER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/twokeyprp.h"
#include <span>

using namespace emp;

// receive the message and reconstruct the tree
// j: position of the secret, begins from 0
void spcot_recv(
    std::span<block> m,
    block secret_sum_f2,
    int depth,
    int choice_pos,
    bool* b,
    bool malicious,
    block* ggm_tree,
    block *chi_alpha,
    block *W) {
  int leave_n = 1<<(depth-1);

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
        if(i+1 != depth-1) {
          for (int j = item_n-2; j >= 0; j-=2) {
            prp.node_expand_2to4(&ggm_tree[j*2], &ggm_tree[j]);
          }
        }
      }

      to_fill_idx += !b[i];
    }
  }

  ggm_tree[choice_pos] = zero_block;
  block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
  block nodes_sum = zero_block;
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

// generate GGM tree, transfer secret, F2^k
std::pair<block, std::vector<block>> spcot_send(
    int depth,
    bool malicious,
    block* ggm_tree,
    block delta,
    block* V) {
  PRG prg;
  block seed;
  prg.random_block(&seed, 1);
  int leave_n = 1 << (depth - 1);
  std::vector<block> m((depth-1) * 2);

  // generate GGM tree from the top
  {
    auto ot_msg_0 = m.data();
    auto ot_msg_1 = m.data() + depth - 1;
    TwoKeyPRP prp = { zero_block, makeBlock(0, 1) };
    prp.node_expand_1to2(ggm_tree, seed);
    ot_msg_0[0] = ggm_tree[0];
    ot_msg_1[0] = ggm_tree[1];
    for(int h = 1; h < depth-1; ++h) {
      ot_msg_0[h] = ot_msg_1[h] = zero_block;
      int sz = 1<<h;
      for(int i = sz-2; i >=0; i-=2) {
        prp.node_expand_2to4(&ggm_tree[i*2], &ggm_tree[i]);
        ot_msg_0[h] = ot_msg_0[h] ^ ggm_tree[i*2];
        ot_msg_0[h] = ot_msg_0[h] ^ ggm_tree[i*2+2];
        ot_msg_1[h] = ot_msg_1[h] ^ ggm_tree[i*2+1];
        ot_msg_1[h] = ot_msg_1[h] ^ ggm_tree[i*2+3];
      }
    }
  }

  auto secret_sum_f2 = zero_block;
  block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
  for(int i = 0; i < leave_n; ++i) {
    ggm_tree[i] = ggm_tree[i] & one;
    secret_sum_f2 = secret_sum_f2 ^ ggm_tree[i];
  }
  secret_sum_f2 = secret_sum_f2 ^ delta;


  if (malicious) {
    // consistency check
    std::vector<block> chi(leave_n);
    Hash hash;
    block digest[2];
    hash.hash_once(digest, &secret_sum_f2, sizeof(block));
    uni_hash_coeff_gen(chi.data(), digest[0], leave_n);

    vector_inn_prdt_sum_red(V, chi.data(), ggm_tree, leave_n);
  }

  return { secret_sum_f2, m };
}

#endif
