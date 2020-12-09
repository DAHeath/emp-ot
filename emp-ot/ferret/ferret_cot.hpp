std::unique_ptr<bool[]> bools_r(std::size_t n) {
  PRG prg;
  std::unique_ptr<bool[]> out(new bool[n]);
  prg.random_bool(out.get(), n);
  return out;
}


template <Role role>
block seed_gen(NetIO& io) {
  block seed;
  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&seed, 1);
    io.send_data(&seed, sizeof(block));
  } else {
    io.recv_data(&seed, sizeof(block));
  }
  io.flush();
  return seed;
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
FerretCOT<role, threads> FerretCOT<role, threads>::make(NetIO* io, bool malicious) {
  FerretCOT out;
  out.io = io;
  out.malicious = malicious;

  if constexpr (role == Role::Sender) {
    PRG prg;
    prg.random_block(&out.delta);
    out.delta = out.delta | 0x1;
  }

  out.ot_pre_data.resize(PRE.n);

  std::unique_ptr<bool[]> choices;
  if constexpr (role == Role::Receiver) {
    choices = bools_r(PRE.m);
  }

  auto init = base_cot<role>(malicious, out.io, out.delta, choices.get(), PRE.m);
  out.extend(PRE, out.ot_pre_data, init);

  return out;
}


// extend f2k in detail
template <Role role, std::size_t threads>
void FerretCOT<role, threads>::extend(
    const MpDesc& desc,
    std::span<block> ot_output,
    std::span<block> ot_input) {
  mpcot<role, threads>(malicious, desc, io, delta, ot_output.data(), ot_input);
  const block seed = seed_gen<role>(*io);
  lpn<role>(desc, seed, threads, ot_output, ot_input.subspan(CONSIST_CHECK_COT_NUM));
}


template <Role role, std::size_t threads>
std::size_t FerretCOT<role, threads>::byte_memory_need_inplace(std::size_t ot_need) {
  std::size_t round = (ot_need - 1) / REGULAR.limit;
  return round * REGULAR.limit + REGULAR.n;
}


// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template <Role role, std::size_t threads>
std::size_t FerretCOT<role, threads>::rcot_inplace(std::span<block> buf) {
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
