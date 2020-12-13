#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_

#include "emp-ot/ferret/lpn_error.h"
#include "emp-ot/ferret/lpn_f2.h"

#include "emp-ot/ferret/role.h"

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


/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
template<Model model, Role role, std::size_t threads>
class FerretCOT {
public:
  block delta;

  static FerretCOT make(NetIO* io);

  std::size_t rcot_inplace(std::span<block>);

  std::size_t byte_memory_need_inplace(std::size_t ot_need);

private:
  NetIO* io;

  std::vector<block> ot_pre_data;

  void extend(
      const MpDesc&,
      std::span<block> ot_output,
      std::span<block> ot_input);
};

#include "emp-ot/ferret/ferret_cot.hpp"
}

#endif// _VOLE_H_
