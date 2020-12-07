#include "test/test.h"
using namespace std;

const static int threads = 1;

int main(int argc, char** argv) {
  int length = 1<<24, port, party;
  parse_party_and_port(argv, &party, &port);

  if (party == ALICE) {
    NetIO* ios[threads+1];
    for(int i = 0; i < threads+1; ++i)
      ios[i] = new NetIO(nullptr, port+i);
    FerretCOT<Role::Sender, threads> ferretcot { ios, false };
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, true)*1e6<<" OTps"<<endl;
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, false)*1e6<<" OTps"<<endl;

    ferretcot = { ios, true };
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, true)*1e6<<" OTps"<<endl;
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, false)*1e6<<" OTps"<<endl;


    for(int i = 0; i < threads+1; ++i) {
      delete ios[i];
    }
  } else {
    NetIO* ios[threads+1];
    for(int i = 0; i < threads+1; ++i)
      ios[i] = new NetIO("127.0.0.1",port+i);
    FerretCOT<Role::Receiver, threads> ferretcot { ios, false };
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, true)*1e6<<" OTps"<<endl;
    cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, false)*1e6<<" OTps"<<endl;
    ferretcot = { ios, true };
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, true)*1e6<<" OTps"<<endl;
    cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, ios[0], party, length, false)*1e6<<" OTps"<<endl;

    for(int i = 0; i < threads+1; ++i) {
      delete ios[i];
    }
  }
}

