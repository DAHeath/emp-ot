#ifndef EMP_FERRET_TWO_KEY_PRP_H__
#define EMP_FERRET_TWO_KEY_PRP_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/gtprp.h"

namespace emp {

//kappa->2kappa PRG, implemented as G(k) = PRF_seed0(k)\xor k || PRF_seed1(k)\xor k
class TwoKeyPRP { public:
  GT::PRP f0;
  GT::PRP f1;

  TwoKeyPRP(std::bitset<128> seed0, std::bitset<128> seed1)
    : f0(seed0), f1(seed1) { }

  inline void node_expand_1to2(std::bitset<128>* children, std::bitset<128> parent) {
    children[1] = parent ^ f1(parent);
    children[0] = parent ^ f0(parent);
  }

  inline void node_expand_2to4(std::bitset<128>* children, std::bitset<128>* parent) {
    children[3] = parent[1] ^ f1(parent[1]);
    children[2] = parent[1] ^ f0(parent[1]);
    children[1] = parent[0] ^ f1(parent[0]);
    children[0] = parent[0] ^ f0(parent[0]);
  }
};

}
#endif
