#ifndef GTPRG_H__
#define GTPRG_H__


#include "gtprp.h"


namespace GT {


struct PRG {
public:
  PRG() : nonce(0) { }
  PRG(PRP f) : f(std::move(f)), nonce(0) { }
  PRG(std::bitset<128> seed) : f(std::move(seed)), nonce(0) { }

  std::bitset<128> operator()() { return f(nonce++); }


  void random_bool(bool* b, std::size_t n) {
    // TODO remove
    std::vector<std::bitset<128>> r((n+127)/128);
    for (auto& slice: r) { slice = (*this)(); }
    for (std::size_t i = 0; i < n; ++i) { b[i] = r[i/128][i%128]; }
  }

private:
  PRP f;
  std::size_t nonce;
};


}


#endif
