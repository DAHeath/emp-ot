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

private:
  PRP f;
  std::size_t nonce;
};


}


#endif
