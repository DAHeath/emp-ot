template <Role role, std::size_t threads>
FerretCOT<role, threads> FerretCOT<role, threads>::make(NetIO* ios[threads+1], bool malicious) {
  FerretCOT out;
  out.io = ios[0];
  out.pool = std::make_unique<ThreadPool>(threads);

  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&out.delta);
    out.delta = out.delta | 0x1;
  }

  BaseCot base_cot(role == Role::Sender ? ALICE : BOB, out.io, malicious);


  // setup
  int party = role == Role::Sender ? ALICE : BOB;
  std::thread thread { [&out, ios, party, malicious] {
    out.mpcot = std::make_unique<MpcotReg<threads>>(malicious, party, N_REG, T_REG, BIN_SZ_REG, out.pool.get(), ios);
    out.pre_ot = std::make_unique<OTPre<NetIO>>(out.io, out.mpcot->tree_height-1, out.mpcot->tree_n);
    out.M = K_REG + out.pre_ot->n + out.mpcot->consist_check_cot_num;
    out.ot_limit = N_REG - out.M;
  }};

  out.ot_pre_data.resize(N_PRE_REG);
  if constexpr (role == Role::Receiver) {
    base_cot.cot_gen_pre();
  } else {
    base_cot.cot_gen_pre(out.delta);
  }

  MpcotReg<threads> mpcot_ini(malicious, party, N_PRE_REG, T_PRE_REG, BIN_SZ_PRE_REG, out.pool.get(), ios);
  OTPre<NetIO> pre_ot_ini(ios[0], mpcot_ini.tree_height-1, mpcot_ini.tree_n);

  std::vector<block> pre_data_ini(K_PRE_REG+mpcot_ini.consist_check_cot_num);
  memset(out.ot_pre_data.data(), 0, N_PRE_REG*16);

  base_cot.cot_gen(&pre_ot_ini, pre_ot_ini.n);
  base_cot.cot_gen(pre_data_ini.data(), K_PRE_REG+mpcot_ini.consist_check_cot_num);
  out.extend(mpcot_ini, pre_ot_ini, N_PRE_REG, K_PRE_REG, out.ot_pre_data, pre_data_ini);

  thread.join();

  return out;
}


// extend f2k in detail
template <Role role, std::size_t threads>
void FerretCOT<role, threads>::extend(
    MpcotReg<threads>& mpcot, OTPre<NetIO>& preot,
    std::size_t n, std::size_t k, std::span<block> ot_output, std::span<block> ot_input) {
  if constexpr (role == Role::Sender) {
    mpcot.sender_init(delta);
  } else {
    mpcot.recver_init();
  }
  mpcot.mpcot(ot_output.data(), &preot, ot_input.data());
  if constexpr (role == Role::Sender) {
    lpn<Role::Sender>(
        n, k, io, threads, ot_output.data(), ot_input.data() + mpcot.consist_check_cot_num);
  } else {
    lpn<Role::Receiver>(
        n, k, io, threads, ot_output.data(), ot_input.data() + mpcot.consist_check_cot_num);
  }
}

template <Role role, std::size_t threads>
std::size_t FerretCOT<role, threads>::byte_memory_need_inplace(std::size_t ot_need) {
  std::size_t round = (ot_need - 1) / ot_limit;
  return round * ot_limit + N_REG;
}

// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template <Role role, std::size_t threads>
std::size_t FerretCOT<role, threads>::rcot_inplace(std::span<block> buf) {
  if (buf.size() < N_REG || (buf.size() - M) % ot_limit != 0) {
    error("Insufficient space. Use `byte_memory_need_inplace` to compute needed space.");
  }
  std::size_t ot_output_n = buf.size() - M;
  std::size_t round = ot_output_n / ot_limit;
  for (std::size_t i = 0; i < round; ++i) {
    if constexpr (role == Role::Sender) {
      pre_ot->send_pre(ot_pre_data.data(), delta);
    } else {
      pre_ot->recv_pre(ot_pre_data.data());
    }
    extend(*mpcot, *pre_ot, N_REG, K_REG, buf, ot_pre_data);
    buf = buf.subspan(ot_limit);
    std::copy(buf.begin(), buf.begin() + M, ot_pre_data.begin());
  }
  return ot_output_n;
}
