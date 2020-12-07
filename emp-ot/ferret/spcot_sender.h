#ifndef SPCOT_SENDER_H__
#define SPCOT_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/twokeyprp.h"

using namespace emp;

// generate GGM tree, transfer secret, F2^k
template <typename OT>
void spcot_send(int depth, bool malicious, OT* ot, NetIO* io, int s, block* ggm_tree, block secret, block* V) {
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
  secret_sum_f2 = secret_sum_f2 ^ secret;


  ot->send(m.data(), &m[depth-1], depth-1, io, s);
  io->send_data(&secret_sum_f2, sizeof(block));
  io->flush();

  if (malicious) {
    // consistency check
    std::vector<block> chi(leave_n);
    Hash hash;
    block digest[2];
    hash.hash_once(digest, &secret_sum_f2, sizeof(block));
    uni_hash_coeff_gen(chi.data(), digest[0], leave_n);

    vector_inn_prdt_sum_red(V, chi.data(), ggm_tree, leave_n);
  }
}

#endif
