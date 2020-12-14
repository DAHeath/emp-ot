#ifndef LPN_ERROR_POINT_H__
#define LPN_ERROR_POINT_H__


#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/role.h"
#include "emp-ot/ferret/twokeyprp.h"
#include "emp-ot/ferret/gtprg.h"
#include <span>

namespace emp {

// receive the message and reconstruct the tree
// j: position of the secret, begins from 0
template <Model model>
void error_point_recv(
    std::span<std::bitset<128>> m,
    std::bitset<128> secret_sum_f2,
    int depth,
    int choice_pos,
    bool* b,
    std::bitset<128>* ggm_tree,
    std::bitset<128> *chi_alpha,
    std::bitset<128> *W) {

  int leave_n = 1<<(depth-1);
  { // gmm tree reconstruction
    int to_fill_idx = 0;
    TwoKeyPRP prp { 0, 1 };
    for (int i = 0; i < depth-1; ++i) {
      // reconstruct a layer of the ggm tree
      to_fill_idx = to_fill_idx * 2;
      ggm_tree[to_fill_idx] = ggm_tree[to_fill_idx+1] = 0;
      int item_n = 1<< (i+1);

      std::bitset<128> nodes_sum = 0;
      for (int j = b[i] != 0; j < item_n; j+=2) {
        nodes_sum ^= ggm_tree[j];
      }

      ggm_tree[to_fill_idx + b[i]] = nodes_sum ^ m[i];
      if (i+1 != depth-1) {
        for (int j = item_n-2; j >= 0; j-=2) {
          /* prp.node_expand_2to4((block*)&ggm_tree[j*2], (block*)&ggm_tree[j]); */
          prp.node_expand_2to4(&ggm_tree[j*2], &ggm_tree[j]);
        }
      }
      to_fill_idx += !b[i];
    }
  }

  ggm_tree[choice_pos] = 0;
  std::bitset<128> one = (std::bitset<128> { 1 }).flip();
  std::bitset<128> nodes_sum = 0;
  for(int i = 0; i < leave_n; ++i) {
    ggm_tree[i] &= one;
    nodes_sum ^= ggm_tree[i];
  }
  ggm_tree[choice_pos] = nodes_sum ^ secret_sum_f2;

  if (model == Model::Malicious) {
    // check consistency
    std::vector<std::bitset<128>> chi(leave_n);
    Hash hash;
    block digest[2];
    hash.hash_once(digest, &secret_sum_f2, sizeof(block));
    uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);
    *chi_alpha = chi[choice_pos];
    vector_inn_prdt_sum_red((block*)W, (block*)chi.data(), (block*)ggm_tree, leave_n);
  }
}

// generate GGM tree, transfer secret, F2^k
template <Model model>
std::pair<std::bitset<128>, std::vector<std::bitset<128>>> error_point_send(
    int depth,
    std::bitset<128>* ggm_tree,
    std::bitset<128> delta,
    std::bitset<128>* V) {
  GT::PRG prg;
  std::bitset<128> seed = prg();
  int leave_n = 1 << (depth - 1);
  std::vector<std::bitset<128>> m((depth-1) * 2);

  // generate GGM tree from the top
  {
    auto ot_msg_0 = m.data();
    auto ot_msg_1 = m.data() + depth - 1;
    TwoKeyPRP prp { 0, 1 };
    prp.node_expand_1to2(ggm_tree, seed);
    ot_msg_0[0] = ggm_tree[0];
    ot_msg_1[0] = ggm_tree[1];
    for(int h = 1; h < depth-1; ++h) {
      ot_msg_0[h] = ot_msg_1[h] = 0;
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

  std::bitset<128> secret_sum_f2 = 0;
  std::bitset<128> one = (std::bitset<128> { 1 }).flip();
  for(int i = 0; i < leave_n; ++i) {
    ggm_tree[i] &= one;
    secret_sum_f2 ^= ggm_tree[i];
  }
  secret_sum_f2 ^= delta;


  if (model == Model::Malicious) {
    // consistency check
    std::vector<std::bitset<128>> chi(leave_n);
    Hash hash;
    block digest[2];
    hash.hash_once(digest, &secret_sum_f2, sizeof(block));
    uni_hash_coeff_gen((block*)chi.data(), digest[0], leave_n);

    vector_inn_prdt_sum_red((block*)V, (block*)chi.data(), (block*)ggm_tree, leave_n);
  }

  return { secret_sum_f2, m };
}

}

#endif
