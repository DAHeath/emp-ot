std::unique_ptr<bool[]> bools_r(std::size_t n) {
  PRG prg;
  std::unique_ptr<bool[]> out(new bool[n]);
  prg.random_bool(out.get(), n);
  return out;
}

template <Role role>
std::vector<block> base_cot(
    bool malicious,
    NetIO* io,
    block delta,
    bool* choices,
    std::size_t n) {
  const auto minusone = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);

  IKNP<NetIO> iknp { io, malicious };

  std::vector<block> buffer(n);
  if constexpr (role == Role::Sender) {
    iknp.setup_send(delta);
    iknp.send_cot(buffer.data(), n);
    io->flush();
    for(int i = 0; i < n; ++i) {
      buffer[i] = buffer[i] & minusone;
    }

  } else {
    iknp.setup_recv();
    iknp.recv_cot(buffer.data(), choices, n);
    block ch[2];
    ch[0] = zero_block;
    ch[1] = makeBlock(0, 1);
    for (int i = 0; i < n; ++i) {
      buffer[i] = (buffer[i] & minusone) ^ ch[choices[i]];
    }
  }
  return buffer;
}

template <Role role, std::size_t threads>
FerretCOT<role, threads> FerretCOT<role, threads>::make(NetIO* ios[threads+1], bool malicious) {
  FerretCOT out;
  out.io = ios[0];
  out.malicious = malicious;
  out.ios = ios;

  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&out.delta);
    out.delta = out.delta | 0x1;
  }

  out.pre_ot = OTPre<role>(out.io, BIN_SZ_REG, T_REG);
  out.M = K_REG + out.pre_ot.n + CONSIST_CHECK_COT_NUM;
  out.ot_limit = N_REG - out.M;
  out.ot_pre_data.resize(N_PRE_REG);

  OTPre<role> pre_ot_ini(ios[0], BIN_SZ_PRE_REG, T_PRE_REG);

  std::size_t num = pre_ot_ini.n + K_PRE_REG + CONSIST_CHECK_COT_NUM;

  std::unique_ptr<bool[]> choices;
  if constexpr (role == Role::Receiver) {
    choices = bools_r(num);
  }

  auto pre_data_ini = base_cot<role>(malicious, out.io, out.delta, choices.get(), num);
  if constexpr (role == Role::Sender) {
    pre_ot_ini.send_pre(pre_data_ini.data(), out.delta);
  } else {
    pre_ot_ini.recv_pre(pre_data_ini.data(), choices.get());
  }

  out.extend(pre_ot_ini, PRE, out.ot_pre_data, pre_data_ini);

  return out;
}


// extend f2k in detail
template <Role role, std::size_t threads>
void FerretCOT<role, threads>::extend(
    OTPre<role>& preot,
    const MpDesc& desc,
    std::span<block> ot_output,
    std::span<block> ot_input) {
  mpcot<role, threads>(malicious, desc, ios, delta, ot_output.data(), &preot, ot_input.data());
  lpn<role>(desc.n, desc.k, io, threads, ot_output.data(), ot_input.data() + CONSIST_CHECK_COT_NUM);
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
      pre_ot.send_pre(ot_pre_data.data(), delta);
    } else {
      pre_ot.recv_pre(ot_pre_data.data());
    }
    extend(pre_ot, REGULAR, buf, ot_pre_data);
    buf = buf.subspan(ot_limit);
    std::copy(buf.begin(), buf.begin() + M, ot_pre_data.begin());
  }
  return ot_output_n;
}
