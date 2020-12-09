#include "test/test.h"
using namespace std;

const static int threads = 1;

int main(int argc, char** argv) {
  int length = 1<<24, port, party;
  parse_party_and_port(argv, &party, &port);

  if (party == ALICE) {
    NetIO io { nullptr, port };
    auto ferretcot = FerretCOT<Role::Sender, threads>::make(&io, false);
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, &io, party, length)*1e6<<" OTps"<<endl;

    ferretcot = FerretCOT<Role::Sender, threads>::make(&io, true);
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, &io, party, length)*1e6<<" OTps"<<endl;
  } else {
    NetIO io { "127.0.0.1",port };
    auto ferretcot = FerretCOT<Role::Receiver, threads>::make(&io, false);
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, &io, party, length)*1e6<<" OTps"<<endl;
    ferretcot = FerretCOT<Role::Receiver, threads>::make(&io, true);
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, &io, party, length)*1e6<<" OTps"<<endl;
  }
}

