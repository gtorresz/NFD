#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include "util/trace_generated.h"
#include "util/initalization_generated.h"
#include "nfd_runner.hpp"

namespace po = boost::program_options;

void
initializeSeed(unsigned Seed){
   fuzz_seed = Seed;
   srand(Seed);
}

void 
readLine(std::string bytes, uint8_t *flatbuffer){
  int k =0;
  for(size_t i=0; i < bytes.size(); i++){
     uint8_t temp = 0;
     if(bytes[i]-'0' > 9)
        temp += (bytes[i]-'a'+10)*16;
     else
        temp += (bytes[i]-'0')*16;
     i++;
     if(bytes[i]-'0' > 9)
        temp += (bytes[i]-'a'+10);
     else
        temp += (bytes[i]-'0');
     flatbuffer[k] = temp;
  //   printf("%02x", temp);
     k++;
  }
}

int
main(int argc, char** argv){

  std::ifstream File(argv[1]);
  std::string bytes;
  getline(File, bytes);
  uint8_t* flatbuffer = ( uint8_t*) malloc(sizeof(uint8_t)*(PACKETSIZE*2));
  readLine(bytes, flatbuffer);
  auto flatbuff = flatbuffers::GetRoot<FuzzTrace::Initial>(flatbuffer);
  initializeSeed(flatbuff->seed());
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  std::clock_t start;
  start = std::clock();
  timeinfo = localtime (&rawtime);
  using namespace nfd;
  std::string configFile = DEFAULT_CONFIG_FILE;
  NfdRunner runner(configFile);
  std::thread ribThread([&runner]{
     runner.initialize();
     return runner.run(NFDmtx, cvar, NFD_Running);
  });
  {  std::unique_lock<std::mutex> lock(NFDmtx);
     cvar.wait(lock,[] {return NFD_Running;});
  }
  ep = boost::asio::local::stream_protocol::endpoint(faces[0]);
  sock.connect(ep);
  Interest inte("setup");
  inte.setCanBePrefix(true);
  Block wireInt = inte.wireEncode();
  boost::asio::ip::tcp::endpoint endpoint( boost::asio::ip::address::from_string("0.0.0.0"), 6363);
  socktcp.connect(endpoint);

  ndn::nfd::CommandOptions options;
  ndn::security::SigningInfo signingInfo;
  options.setSigningInfo(signingInfo);
  ControlParameters parameters;
  shared_ptr<ControlCommand> command;
  Name requestName;
  ndn::KeyChain keyChain;
  ndn::security::CommandInterestSigner m_signer(keyChain);
  Interest interest;
  ndn::Block wire;
  boost::asio::ip::udp::endpoint endpoint1(
                         boost::asio::ip::address::from_string("0.0.0.0"), 6363);
  sockudp.connect(endpoint1);
  sockudp.send(boost::asio::buffer(wireInt.wire(), wireInt.size()));
  
  for(int k = 0; k < PREFIXES; k++){
    auto tempstring = flatbuff->prefixes()->Get(k);
     Name prefix(tempstring->str());
     std::cout<<flatbuff->faces()->Get(k)<<std::endl;
     parameters = ndn::nfd::ControlParameters().setName(prefix).setFlags(0).setFaceId(256+flatbuff->faces()->Get(k));
     command = make_shared<ndn::nfd::RibRegisterCommand>();
     requestName = command->getRequestName(options.getPrefix(), parameters);
     interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());
     interest.setInterestLifetime(options.getTimeout());
     wire = interest.wireEncode();
     sock.send(boost::asio::buffer(wire.wire(), wire.size()));

     auto strat = flatbuff->strategies()->Get(k)->str();
     parameters = ndn::nfd::ControlParameters().setName(prefix).setStrategy("ndn:/localhost/nfd/strategy/"+strat);
     command = make_shared<ndn::nfd::StrategyChoiceSetCommand>();
     requestName = command->getRequestName(options.getPrefix(), parameters);
     interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());
     interest.setInterestLifetime(options.getTimeout());
     wire = interest.wireEncode();
     sock.send(boost::asio::buffer(wire.wire(), wire.size()));
  }
  string input;
  while(getline(File, input)) {
    std::cout<<"Testing...\n";
     readLine(input, flatbuffer);
     auto flatData = flatbuffers::GetRoot<FuzzTrace::Input>(flatbuffer);
     uint8_t *flatint = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
     uint8_t *flatdata = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
     int faceid = flatData->face();
     auto testf = flatData->prefix()->str();
     auto fint = flatData->interest();
     std::copy(fint->begin(), fint->end(), &flatint[0]);
     auto fdata = flatData->data();
     std::copy(fdata->begin(), fdata->end(), flatdata);
     ndn::Block wireInt(flatint,fint->size());
     wireInt.parse();

     Interest inte("hu/what");
     inte.setCanBePrefix(true);
     Block wire = inte.wireEncode();
     inte.wireDecode(wireInt);
     inte.setName(ndn::Name(testf+inte.getName().toUri()));
     wireInt = inte.wireEncode();
     inte.wireDecode(wireInt);
     if(faceid == 0)
        sock.send(boost::asio::buffer(wireInt.wire(), wireInt.size()));
     else if(faceid == 1)
        socktcp.send(boost::asio::buffer(wireInt.wire(), wireInt.size()));
     else
        sockudp.send(boost::asio::buffer(wireInt.wire(), wireInt.size()));
     if(fdata->size()!=0){
        ndn::Block wire1(flatdata,fdata->size());
	wire1.parse();
	if(faceid == 0)
           sock.send(boost::asio::buffer(wire1.wire(), wire1.size()));
	else if(faceid == 1)
           socktcp.send(boost::asio::buffer(wire1.wire(), wire1.size()));
	else
           sockudp.send(boost::asio::buffer(wire1.wire(), wire1.size()));
     }
     struct timeval t1;
     t1.tv_usec = 1000;
     select(0, NULL, NULL, NULL, &t1);
//     usleep(1000);
  }

  free(flatbuffer);
  std::cout<<"done\n";
  getMainIoService().stop();
  //ribThread.join();
  return 0;
}

