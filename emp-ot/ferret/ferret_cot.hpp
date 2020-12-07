template <int threads>
FerretCOT<threads>::FerretCOT(int party, NetIO* ios[threads+1], bool malicious) {
  this->party = party;
  io = ios[0];
  this->ios = ios;
  this->is_malicious = malicious;
  BaseCot base_cot(party, io, malicious);
  pool = std::make_unique<ThreadPool>(threads);

  if (party == ALICE) {
    PRG prg;
    prg.random_block(&Delta);
    Delta = Delta | 0x1;
    setup(base_cot, Delta);
  } else {
    setup(base_cot);
  }
}

// extend f2k in detail
template<int threads>
void FerretCOT<threads>::extend(
    int party, int n, int k, NetIO* io,
    block* ot_output, MpcotReg<threads> *mpcot, OTPre<NetIO> *preot, block *ot_input) {
  if(party == ALICE) mpcot->sender_init(Delta);
  else mpcot->recver_init();
  mpcot->mpcot(ot_output, preot, ot_input);
  if (party == ALICE) {
    lpn<Role::Sender>(n, k, io, threads, ot_output, ot_input+mpcot->consist_check_cot_num);
  } else {
    lpn<Role::Receiver>(n, k, io, threads, ot_output, ot_input+mpcot->consist_check_cot_num);
  }
}

// extend f2k (customized location)
template<int threads>
void FerretCOT<threads>::extend_f2k(block *ot_buffer) {
  if(party == ALICE) {
    pre_ot->send_pre(ot_pre_data.data(), Delta);
  } else {
    pre_ot->recv_pre(ot_pre_data.data());
  }
  extend(party, N_REG, K_REG, io, ot_buffer, mpcot.get(), pre_ot.get(), ot_pre_data.data());
  memcpy(ot_pre_data.data(), ot_buffer+ot_limit, M*sizeof(block));
  ot_used = 0;
}

template<int threads>
void FerretCOT<threads>::setup(BaseCot& base_cot, block Deltain) {
  this->Delta = Deltain;
  setup(base_cot);
}

template<int threads>
void FerretCOT<threads>::setup(BaseCot& base_cot) {
  ThreadPool pool2(1);

  std::thread thread { [this] {
    mpcot = std::make_unique<MpcotReg<threads>>(is_malicious, party, N_REG, T_REG, BIN_SZ_REG, pool.get(), ios);
    pre_ot = std::make_unique<OTPre<NetIO>>(io, mpcot->tree_height-1, mpcot->tree_n);
    M = K_REG + pre_ot->n + mpcot->consist_check_cot_num;
    ot_limit = N_REG - M;
    ot_used = ot_limit;
  }};

  ot_pre_data.resize(N_PRE_REG);
  if (party == BOB) {
    base_cot.cot_gen_pre();
  } else {
    base_cot.cot_gen_pre(Delta);
  }

  MpcotReg<threads> mpcot_ini(is_malicious, party, N_PRE_REG, T_PRE_REG, BIN_SZ_PRE_REG, pool.get(), ios);
  OTPre<NetIO> pre_ot_ini(ios[0], mpcot_ini.tree_height-1, mpcot_ini.tree_n);

  block pre_data_ini[K_PRE_REG+mpcot_ini.consist_check_cot_num];
  memset(ot_pre_data.data(), 0, N_PRE_REG*16);

  base_cot.cot_gen(&pre_ot_ini, pre_ot_ini.n);
  base_cot.cot_gen(pre_data_ini, K_PRE_REG+mpcot_ini.consist_check_cot_num);
  extend(party, N_PRE_REG, K_PRE_REG, io, ot_pre_data.data(), &mpcot_ini, &pre_ot_ini, pre_data_ini);

  thread.join();
}

template<int threads>
void FerretCOT<threads>::rcot(block* data, int num) {
  ot_data.resize(N_REG);
  if (num <= ot_limit - ot_used) {
    memcpy(data, ot_data.data()+ot_used, num*sizeof(block));
    ot_used += num;
    return;
  } else {
    int gened = ot_limit - ot_used;
    memcpy(data, ot_data.data()+ot_used, gened*sizeof(block));
    data += gened;

    int round_inplace = (num-gened-M) / ot_limit;
    int last_round_ot = num - gened - round_inplace*ot_limit;
    bool round_memcpy = last_round_ot > ot_limit;
    for (int i = 0; i < round_inplace; ++i) {
      extend_f2k(data);
      ot_used = ot_limit;
      data += ot_limit;
    }
    if (round_memcpy) {
      last_round_ot -= ot_limit;
      extend_f2k(ot_data.data());
      memcpy(data, ot_data.data(), ot_limit*sizeof(block));
      data += ot_limit;
    }
    if (last_round_ot > 0) {
      extend_f2k(ot_data.data());
      memcpy(data, ot_data.data(), last_round_ot*sizeof(block));
      ot_used = last_round_ot;
    }
  }
}

template<int threads>
uint64_t FerretCOT<threads>::byte_memory_need_inplace(uint64_t ot_need) {
  int round = (ot_need - 1) / ot_limit;
  return round * ot_limit + N_REG;
}

// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template<int threads>
uint64_t FerretCOT<threads>::rcot_inplace(block *ot_buffer, int byte_space) {
  if(byte_space < N_REG) error("space not enough");
  if((byte_space - M) % ot_limit != 0) error("call byte_memory_need_inplace \
      to get the correct length of memory space");
  uint64_t ot_output_n = byte_space - M;
  int round = ot_output_n / ot_limit;
  block *pt = ot_buffer;
  for(int i = 0; i < round; ++i) {
    if (party == ALICE) {
      pre_ot->send_pre(ot_pre_data.data(), Delta);
    } else {
      pre_ot->recv_pre(ot_pre_data.data());
    }
    extend(
        party, N_REG, K_REG, io,
        pt, mpcot.get(), pre_ot.get(), ot_pre_data.data());
    pt += ot_limit;
    memcpy(ot_pre_data.data(), pt, M*sizeof(block));
  }
  return ot_output_n;
}
