#ifndef DPF_H__
#define DPF_H__


#include "emp-ot/ferret/role.h"
#include "emp-ot/ferret/gtprg.h"

#include <span>


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


std::vector<std::pair<std::bitset<128>, std::bitset<128>>>
dpf_send(std::size_t depth, std::bitset<128> seed, std::span<std::bitset<128>> tar) {
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


void dpf_recv(
    std::size_t depth,
    std::span<const bool> choices,
    std::span<const std::bitset<128>> stacks,
    std::span<std::bitset<128>> tar) {
  std::size_t ptr = 0;
  for (int i = 0; i < depth-1; ++i) {
    // reconstruct a layer of the ggm tree
    tar[ptr] = tar[ptr+1] = 0;
    int item_n = 1<< (i+1);

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



#endif
