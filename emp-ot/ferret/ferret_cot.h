#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ferret/mpcot_reg.h"
#include "emp-ot/ferret/base_cot.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/ferret/constants.h"

#include "emp-ot/ferret/role.h"

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
template<Role role, int threads>
class FerretCOT {
public:
  NetIO* io;
  block Delta;

  int ot_used, ot_limit;

  FerretCOT(NetIO* ios[threads+1], bool malicious = false);

  void setup(BaseCot&, block Deltain);
  void setup(BaseCot&);

  void rcot(block *data, int num);
  uint64_t rcot_inplace(block *ot_buffer, int length);

  uint64_t byte_memory_need_inplace(uint64_t ot_need);

private:
  NetIO **ios;
  int M;
  bool is_malicious;

  std::vector<block> ot_pre_data;
  std::vector<block> ot_data;

  std::unique_ptr<OTPre<NetIO>> pre_ot;
  std::unique_ptr<ThreadPool> pool;
  std::unique_ptr<MpcotReg<threads>> mpcot;

  void extend(
      int n, int k, NetIO* io,
      block* ot_output, MpcotReg<threads> *mpfss, OTPre<NetIO> *preot, block *ot_input);

  void extend_f2k(block *ot_buffer);

  void extend_f2k();
};

#include "emp-ot/ferret/ferret_cot.hpp"
}
#endif// _VOLE_H_
