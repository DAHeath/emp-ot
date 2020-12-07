#ifndef EMP_FERRET_CONSTANTS_H__
#define EMP_FERRET_CONSTANTS_H__

namespace emp {

static std::string PRE_OT_DATA_REG_SEND_FILE = "./data/pre_ot_data_reg_send";
static std::string PRE_OT_DATA_REG_RECV_FILE = "./data/pre_ot_data_reg_recv";

constexpr int N_REG = 10608640;
constexpr int T_REG = 1295;
constexpr int K_REG = 589824;
constexpr int BIN_SZ_REG = 13;
constexpr int N_PRE_REG = 649728;
constexpr int T_PRE_REG = 1269;
constexpr int K_PRE_REG = 36288;
constexpr int BIN_SZ_PRE_REG = 9;

}

#endif
