template <Model model, Role role>
std::vector<block> base_cot(
    NetIO* io,
    block delta,
    bool* choices,
    std::size_t n) {
  const auto minusone = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);

  bool malicious = model == Model::Malicious;
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


template <Model model, Role role, std::size_t threads>
FerretCOT<model, role, threads> FerretCOT<model, role, threads>::make(NetIO* io) {
  FerretCOT out;
  out.io = io;

  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&out.delta);
    out.delta = out.delta | 0x1;
  }

  std::unique_ptr<bool[]> choices;
  if constexpr (role == Role::Receiver) {
    PRG prg;
    choices = std::unique_ptr<bool[]>(new bool[PRE.m]);
    prg.random_bool(choices.get(), PRE.m);
  }

  auto init = base_cot<model, role>(out.io, out.delta, choices.get(), PRE.m);

  out.ot_pre_data.resize(PRE.n);
  out.extend(PRE, out.ot_pre_data, init);

  return out;
}


// extend f2k in detail
template <Model model, Role role, std::size_t threads>
void FerretCOT<model, role, threads>::extend(
    const MpDesc& desc,
    std::span<block> tar,
    std::span<block> src) {
  block seed;
  { // gen seed
    if constexpr (role == Role::Sender) {
      PRG prg;
      prg.random_block(&seed, 1);
      io->send_data(&seed, sizeof(block));
    } else {
      io->recv_data(&seed, sizeof(block));
    }
    io->flush();
  }
  lpn_error<model, role, threads>(desc, io, delta, tar.data(), src);
  sparse_linear_code<role>(desc, seed, threads, tar, src.subspan(CONSIST_CHECK_COT_NUM));
}


template <Model model, Role role, std::size_t threads>
std::size_t FerretCOT<model, role, threads>::byte_memory_need_inplace(std::size_t ot_need) {
  std::size_t round = (ot_need - 1) / REGULAR.limit;
  return round * REGULAR.limit + REGULAR.n;
}


// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template <Model model, Role role, std::size_t threads>
std::size_t FerretCOT<model, role, threads>::rcot_inplace(std::span<block> buf) {
  if (buf.size() < REGULAR.n || (buf.size() - REGULAR.m) % REGULAR.limit != 0) {
    error("Insufficient space. Use `byte_memory_need_inplace` to compute needed space.");
  }
  std::size_t ot_output_n = buf.size() - REGULAR.m;
  std::size_t round = ot_output_n / REGULAR.limit;
  for (std::size_t i = 0; i < round; ++i) {
    extend(REGULAR, buf, ot_pre_data);
    buf = buf.subspan(REGULAR.limit);
    std::copy(buf.begin(), buf.begin() + REGULAR.m, ot_pre_data.begin());
  }
  return ot_output_n;
}
