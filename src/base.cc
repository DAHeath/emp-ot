#include "base.h"
#include "point.h"
#include "gthash.h"
#include "gtprg.h"
#include "link.h"

using namespace GT;

namespace BaseOT {

std::vector<std::bitset<128>> randomBlock(PRG& prg, std::size_t n) {
  std::vector<std::bitset<128>> out(n);
  for (auto& o : out) { o = prg(); }
  return out;
}


template <std::size_t n>
std::bitset<128*n> randomBits(PRG& prg) {
  std::bitset<128*n> out;
  std::bitset<128>* arr = (std::bitset<128>*)&out;
  for (std::size_t i = 0; i < n; ++i) { arr[i] = prg(); }
  return out;
}


template <std::size_t n>
std::bitset<128*n> randomBits() {
  PRG prg;
  return randomBits<n>(prg);
}

std::pair<std::vector<std::bitset<128>>, std::vector<std::bitset<128>>>
send(Link& link) {
  constexpr std::size_t n = 128;

  Group G;
  const auto a = G.randBigInt();
  const auto A = G * a;
  A.write(link);
  const auto AaInv = ~(A * a);

  std::vector<Point> B(n);
  std::vector<Point> BA(n);
  for(int i = 0; i < n; ++i) {
    B[i] = Point::read(G, link) * a;
    BA[i] = B[i] + AaInv;
  }

  PRG prg;
  const auto k0 = randomBlock(prg, 128);
  const auto k1 = randomBlock(prg, 128);

  for(int i = 0; i < n; ++i) {
    std::bitset<128> payload[2];
    payload[0] = k0[i] ^ B[i].hash(i);
    payload[1] = k1[i] ^ BA[i].hash(i);
    link.send((const std::byte*)payload, 2*sizeof(std::bitset<128>));
  }
  link.flush();
  return { k0, k1 };
}


std::vector<std::bitset<128>>
recv(Link& link, const std::bitset<128>& b) {
  constexpr std::size_t n = 128;

  Group G;
  Point A = Point::read(G, link);

  std::vector<BigInt> bb(n);
  for(int i = 0; i < n; ++i) {
    bb[i] = G.randBigInt();
    const auto B = b[i] ? (G * bb[i]) + A : G * bb[i];
    B.write(link);
  }
  link.flush();

  std::vector<std::bitset<128>> data(n);
  for(int i = 0; i < n; ++i) {
    std::bitset<128> res[2];
    link.recv(std::span<std::byte> { (std::byte*)res, 2*sizeof(std::bitset<128>) });
    data[i] = (A * bb[i]).hash(i) ^ (b[i] ? res[1] : res[0]);
  }
  return data;
}

}
