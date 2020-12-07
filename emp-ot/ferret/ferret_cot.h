#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_

#include "emp-ot/ferret/mpcot_reg.h"
#include "emp-ot/ferret/lpn_f2.h"

#include "emp-ot/ferret/role.h"

#include <span>

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
template<Role role, std::size_t threads>
class FerretCOT {
public:
  NetIO* io;
  block delta;

  static FerretCOT make(NetIO* ios[threads+1], bool malicious = false);

  void rcot(block *data, std::size_t num);
  std::size_t rcot_inplace(std::span<block>);

  std::size_t byte_memory_need_inplace(std::size_t ot_need);

private:
  static constexpr std::size_t N_REG = 10608640;
  static constexpr std::size_t T_REG = 1295;
  static constexpr std::size_t K_REG = 589824;
  static constexpr std::size_t BIN_SZ_REG = 13;
  static constexpr std::size_t N_PRE_REG = 649728;
  static constexpr std::size_t T_PRE_REG = 1269;
  static constexpr std::size_t K_PRE_REG = 36288;
  static constexpr std::size_t BIN_SZ_PRE_REG = 9;

  std::size_t ot_limit;

  std::size_t M;

  std::vector<block> ot_pre_data;

  std::unique_ptr<OTPre<NetIO>> pre_ot;
  std::unique_ptr<MpcotReg<threads>> mpcot;

  void extend(
      MpcotReg<threads>&, OTPre<NetIO>&, std::size_t n, std::size_t k,
      std::span<block> ot_output, std::span<block> ot_input);
};

#include "emp-ot/ferret/ferret_cot.hpp"
}
#endif// _VOLE_H_
