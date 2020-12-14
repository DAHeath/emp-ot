#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_

#include "emp-ot/ferret/lpn_error.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/ferret/role.h"
#include "emp-ot/ferret/gtprg.h"

#include <span>

namespace emp {


static constexpr MpDesc REGULAR = {
  .n = 10608640,
  .k = 589824,
  .t = 1295,
  .bin_sz = 13,
  .m = 589824 + 13*1295 + CONSIST_CHECK_COT_NUM,
  .mask = 0xFFFFF,
  .limit = 10608640 - (589824 + 13*1295 + CONSIST_CHECK_COT_NUM),
};


static constexpr MpDesc PRE = {
  .n = 649728,
  .k = 36288,
  .t = 1269,
  .bin_sz = 9,
  .m = 36288 + 9*1269 + CONSIST_CHECK_COT_NUM,
  .mask = 0xFFFF,
  .limit = 649728 - (36288 + 9*1269 + CONSIST_CHECK_COT_NUM),
};


template <Model model, Role role>
std::vector<std::bitset<128>> base_cot(
    NetIO& io,
    std::bitset<128> delta,
    bool* choices,
    std::size_t n) {
  const auto minusone = std::bitset<128>(1).flip();

  bool malicious = model == Model::Malicious;
  IKNP<NetIO> iknp { &io, malicious };

  std::vector<std::bitset<128>> buffer(n);
  if constexpr (role == Role::Sender) {
    block delta2;
    memcpy(&delta2, &delta, sizeof(delta));
    iknp.setup_send(delta2);
    iknp.send_cot((block*)buffer.data(), n);
    io.flush();
    for(int i = 0; i < n; ++i) {
      buffer[i] = buffer[i] & minusone;
    }

  } else {
    iknp.setup_recv();
    iknp.recv_cot((block*)buffer.data(), choices, n);
    std::bitset<128> ch[2];
    ch[0] = 0;
    ch[1] = 1;
    for (int i = 0; i < n; ++i) {
      buffer[i] = (buffer[i] & minusone) ^ ch[choices[i]];
    }
  }
  return buffer;
}


/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 */
template<Model model, Role role, std::size_t threads>
struct FerretCOT {
  std::bitset<128> delta;
  std::vector<std::bitset<128>> small_correlation;

  static FerretCOT make(NetIO& io) {
    FerretCOT out;

    if constexpr (role == Role::Sender) {
      GT::PRG prg;
      out.delta = prg() | std::bitset<128> { 1 };
    }

    std::unique_ptr<bool[]> choices;
    if constexpr (role == Role::Receiver) {
      PRG prg;
      choices = std::unique_ptr<bool[]>(new bool[PRE.m]);
      prg.random_bool(choices.get(), PRE.m);
    }

    auto init = base_cot<model, role>(io, out.delta, choices.get(), PRE.m);

    out.small_correlation.resize(PRE.n);
    out.lpn_extension(PRE, io, out.small_correlation, init);

    return out;
  }

  std::size_t extend(NetIO& io, std::span<std::bitset<128>> buf) {
    if (buf.size() < REGULAR.n || (buf.size() - REGULAR.m) % REGULAR.limit != 0) {
      error("Insufficient space. Use `byte_memory_need_inplace` to compute needed space.");
    }
    std::size_t ot_output_n = buf.size() - REGULAR.m;
    std::size_t round = ot_output_n / REGULAR.limit;
    for (std::size_t i = 0; i < round; ++i) {
      lpn_extension(REGULAR, io, buf, small_correlation);
      buf = buf.subspan(REGULAR.limit);
      std::copy(buf.begin(), buf.begin() + REGULAR.m, small_correlation.begin());
    }
    return ot_output_n;
  }

  std::vector<std::bitset<128>> extend(NetIO& io, std::size_t n) {
    std::vector<std::bitset<128>> out(byte_memory_need_inplace(n));
    extend(io, out);
    return out;
  }

  std::size_t byte_memory_need_inplace(std::size_t ot_need) {
    std::size_t round = (ot_need - 1) / REGULAR.limit;
    return round * REGULAR.limit + REGULAR.n;
  }

  void lpn_extension(const MpDesc& desc, NetIO& io, std::span<std::bitset<128>> tar, std::span<std::bitset<128>> src) {
    std::bitset<128> seed;
    { // gen seed
      if constexpr (role == Role::Sender) {
        GT::PRG prg;
        seed = prg();
        io.send_data(&seed, sizeof(std::bitset<128>));
      } else {
        io.recv_data(&seed, sizeof(std::bitset<128>));
      }
      io.flush();
    }
    lpn_error<model, role, threads>(desc, &io, delta, tar.data(), src);
    sparse_linear_code<role>(desc, seed, threads, tar, src.subspan(CONSIST_CHECK_COT_NUM));
  }
};

}

#endif
