#ifndef LPN_ERROR_POINT_H__
#define LPN_ERROR_POINT_H__


#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/role.h"
#include "emp-ot/ferret/gtprg.h"
#include <span>

namespace emp {


void ggm_expand(
    const std::bitset<128>& parent,
    std::bitset<128>& child0,
    std::bitset<128>& child1) {
  static GT::PRP f0(0);
  static GT::PRP f1(1);
  child0 = f0(parent);
  child1 = f1(parent);
}


// receive the message and reconstruct the tree
// j: position of the secret, begins from 0
template <Model model>
std::pair<std::bitset<128>, std::bitset<128>> error_point_recv(
    std::span<std::bitset<128>> m,
    std::bitset<128> secret_sum_f2,
    int tree_height,
    int choice_pos,
    bool* b,
    std::bitset<128>* ggm_tree) {

  int leave_n = 1<<(tree_height-1);
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
    auto chi_alpha = chi[choice_pos];
    std::bitset<128> W;
    vector_inn_prdt_sum_red((block*)&W, (block*)chi.data(), (block*)ggm_tree, leave_n);
    return { chi_alpha, W };
  } else {
    return { 0, 0 };
  }
}

// generate GGM tree, transfer secret, F2^k
template <Model model>
std::pair<std::bitset<128>, std::vector<std::bitset<128>>> error_point_send(
    std::size_t tree_height,
    std::bitset<128>* ggm_tree,
    std::bitset<128> delta,
    std::bitset<128>* V) {
  GT::PRG prg;
  std::bitset<128> seed = prg();
  std::size_t leave_n = 1 << (tree_height - 1);
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

  std::bitset<128> secret_sum_f2 = 0;
  std::bitset<128> one = (std::bitset<128> { 1 }).flip();
  for (std::size_t i = 0; i < leave_n; ++i) {
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
