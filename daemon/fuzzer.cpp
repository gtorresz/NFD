/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nfd.hpp"
#include "rib/service.hpp"

#include "common/global.hpp"
#include "common/logger.hpp"
#include "common/privilege-helper.hpp"
#include "core/version.hpp"
#include <time.h>
#include <string.h> // for strsignal()
#include <sys/select.h>

#include <boost/config.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/version.hpp>

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>
#include <ndn-cxx/util/logging.hpp>
#include <ndn-cxx/version.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>
#include "face/unix-stream-transport.hpp"
#include "fuzzUtil/mutator.hpp"
#include <ndn-cxx/fuzzer-seed.hpp>
#include "face/pcap-helper.hpp"
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include "fuzzUtil/trace_generated.h"
#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#ifdef HAVE_WEBSOCKET
#include <websocketpp/version.hpp>
#endif
#define PREFIXES 50
#define PACKETSIZE 4096
namespace po = boost::program_options;

NFD_LOG_INIT(Main);

namespace nfd {

/** \brief Executes NFD with RIB manager
 *
 *  NFD (main forwarding procedure) and RIB manager execute in two different threads.
 *  Each thread has its own instances of global io_service and global scheduler.
 *
 *  When either of the daemons fails, execution of non-failed daemon will be terminated as
 *  well.  In other words, when NFD fails, RIB manager will be terminated; when RIB manager
 *  fails, NFD will be terminated.
 */
class NfdRunner : noncopyable
{
public:
  explicit
  NfdRunner(const std::string& configFile)
    : m_nfd(configFile, m_nfdKeyChain)
    , m_configFile(configFile)
    , m_terminationSignalSet(getGlobalIoService())
    , m_reloadSignalSet(getGlobalIoService())
  {
    m_terminationSignalSet.add(SIGINT);
    m_terminationSignalSet.add(SIGTERM);
    m_terminationSignalSet.async_wait(bind(&NfdRunner::terminate, this, _1, _2));
 
     m_reloadSignalSet.add(SIGHUP);
    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));
  }

  void
  initialize()
  {
    m_nfd.initialize();
  }
  
  void
  addFibentry(ndn::Name Prefix)
  {
  m_nfd.addFibentry(Prefix);
  }

  int
  run(std::mutex& NFDmtx, std::condition_variable& cvar, bool& NFD_Running)
  {
    // Return value: a non-zero value is assigned when either NFD or RIB manager (running in
    // a separate thread) fails.
    std::atomic_int retval(0);

    boost::asio::io_service* const mainIo = &getGlobalIoService();
    setMainIoService(mainIo);
    boost::asio::io_service* ribIo = nullptr;

    // Mutex and conditional variable to implement synchronization between main and RIB manager
    // threads:
    // - to block main thread until RIB manager thread starts and initializes ribIo (to allow
    //   stopping it later)
    std::mutex m;
    std::condition_variable cv;

    std::thread ribThread([configFile = m_configFile, &retval, &ribIo, mainIo, &cv, &m] {
      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = &getGlobalIoService();
        BOOST_ASSERT(ribIo != mainIo);
        setRibIoService(ribIo);
      }
      cv.notify_all(); // notify that ribIo has been assigned

      try {
        ndn::KeyChain ribKeyChain;
        // must be created inside a separate thread
        rib::Service ribService(configFile, ribKeyChain);
        getGlobalIoService().run(); // ribIo is not thread-safe to use here
      }
      catch (const std::exception& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        retval = 1;
        mainIo->stop();
      }

      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = nullptr;
      }
    });

    {
      // Wait to guarantee that ribIo is properly initialized, so it can be used to terminate
      // RIB manager thread.
      std::unique_lock<std::mutex> lock(m);
      cv.wait(lock, [&ribIo] { return ribIo != nullptr; });
    }
    
    {
       std::lock_guard<std::mutex> lock(NFDmtx);
       NFD_Running = true;
       cvar.notify_all();
    }

    try {
      systemdNotify("READY=1");
      mainIo->run();
    }
    catch (const std::exception& e) {
      NFD_LOG_FATAL(boost::diagnostic_information(e));
      retval = 1;
    }
    catch (const PrivilegeHelper::Error& e) {
      NFD_LOG_FATAL(e.what());
      retval = 4;
    }
    {
  // ribIo is guaranteed to be alive at this point
      std::lock_guard<std::mutex> lock(m);
      if (ribIo != nullptr) {
        ribIo->stop();
        ribIo = nullptr;
      }
    }
    
    ribThread.join();


    return retval;
  }

  static void
  systemdNotify(const char* state)
  {
#ifdef HAVE_SYSTEMD
    sd_notify(0, state);
#endif
  }

private:
  void
  terminate(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), exiting...");

    systemdNotify("STOPPING=1");
    getGlobalIoService().stop();
    std::cout<<"\n\n\n\n\n\n\n\nI am broken....\n\n\n\n\n\n\n\n";
  }

  void
  reload(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), reloading...");

    systemdNotify("RELOADING=1");
    m_nfd.reloadConfigFile();
    systemdNotify("READY=1");

    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));
  }

private:
  ndn::KeyChain           m_nfdKeyChain;
  Nfd                     m_nfd;
  std::string             m_configFile;

  boost::asio::signal_set m_terminationSignalSet;
  boost::asio::signal_set m_reloadSignalSet;
};

} // namespace nfd

size_t DataCustomMutator(ndn::Block temp, uint8_t *inter, uint8_t *Dat, size_t Size,
                                          size_t MaxSize, unsigned int Seed);
int *k;
char fr[100000];
char ***c;
ndn::Mutator mutator;
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
   k = argc;
   c = argv;
   return 0;
}
// ndn::Mutator mutator;

size_t constructInterest(uint8_t *sendBytes, ndn::Block inter, uint8_t* Dat, size_t Size){
   ndn::Interest interest;
   size_t totalLength = 0;
   ndn::EncodingEstimator estimator;
   interest.wireDecode(inter);
   size_t estimatedSize = interest.wireEncode(estimator);
   ndn::EncodingBuffer encoder(estimatedSize, 0);
   ndn::Block wire(Dat, Size);
   wire.parse();
   ndn::Block temp(interest.wireEncode());

  for(size_t i=0;i<temp.elements_size();i++){
     if(temp.elements()[i].type()==ndn::tlv::Name)
        totalLength += encoder.appendByteArrayBlock(ndn::tlv::Name, wire.elements()[0].value(), wire.elements()[0].value_size());
     else
        totalLength += encoder.appendByteArrayBlock(temp.elements()[i].type(), temp.elements()[i].value(), temp.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(ndn::tlv::Interest);
  for(size_t i= 0; i< encoder.block().size(); i++){
     sendBytes[i] = encoder.block().wire()[i];
  }
  return totalLength;
}


boost::asio::io_service m_ioService;
boost::asio::local::stream_protocol::endpoint ep;
boost::asio::local::stream_protocol::socket sock(m_ioService);
boost::asio::io_service m_ioService1;
boost::asio::local::stream_protocol::socket sock1(m_ioService1);
boost::asio::io_service m_ioService2;
boost::asio::local::stream_protocol::socket sock2(m_ioService2);
boost::asio::io_service m_ioServiceTCP;
boost::asio::ip::tcp::socket socktcp(m_ioServiceTCP);
boost::asio::io_service m_ioServiceUDP;
boost::asio::ip::udp::socket sockudp(m_ioServiceUDP);
boost::asio::ip::udp::socket sockudp1(m_ioServiceUDP);
uint8_t interests[1000][PACKETSIZE];
uint8_t dataPks[300][PACKETSIZE];
uint8_t dbytes[PACKETSIZE];
ndn::Name prefixes[PREFIXES];
size_t sizes[1000];
size_t dataSizes[1000];
int seed;
int dpos =0;
std::vector<std::string> faces = {"/run/nfd.sock","tcp4://0.0.0.0:6363","udp4://0.0.0.0:6363" };
int faceNum = 3;
int faceUses[3] = {0,0,0};
std::vector<std::string> strats = {"best-route","access","asf","multicast","self-learning","ncc"};
int stratNum = 6;
int stratUses[6] = {0,0,0,0,0,0};
std::unordered_map<std::string,std::string> prefixStrat;
std::mutex mtx;
std::mutex seedMtx;
std::mutex NFDmtx;
std::condition_variable cvar;
bool setupComplete = false;
bool NFD_Running = false;


extern "C" int 
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
	
  {
     std::unique_lock<std::mutex> lock(mtx);
     cvar.wait(lock,[] {return setupComplete; });  
  }

  using namespace nfd;
  if(Size <= 2 )return 0;

  uint8_t *buf = ( uint8_t*) malloc(sizeof(uint8_t)*Size);
  std::copy(&Data[0], &Data[Size], &buf[0]);
  auto flatData = flatbuffers::GetRoot<FuzzTrace::Input>(buf);
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
  FILE* fp = fopen (fr, "a");
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
  //const uint8_t* writeBytes = wireInt.wire();
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
  for(size_t i = 0;i<Size; i++)
     fprintf(fp,"%02x", Data[i]);
  fprintf(fp, "\n");
  fclose(fp);
  free(flatdata);
  free(flatint);
  free(buf);
  return 0;
}
bool seedSet =false;
extern "C" void
initializeSeed(unsigned Seed){
   std::lock_guard<std::mutex> lock(seedMtx);
   fuzz_seed = Seed;
   seedSet = true;
   srand(Seed);
   cvar.notify_all();  
}

extern "C" void
SetUp(){
  {
     std::unique_lock<std::mutex> lock(seedMtx);
     cvar.wait(lock,[] {return seedSet; });
  }
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  std::clock_t start;
  start = std::clock();
  timeinfo = localtime (&rawtime);
  sprintf(fr, "FuzzerTrace/packetTrace.csv");
  using namespace nfd;
  FILE* fp = fopen (fr, "w");
  fprintf(fp, "packetType,face,bytes\n");
  fclose(fp);
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
int preCount = 0;
  for(int k = 0; k < PREFIXES; k++){
     int prefixBase = 0;
     if(preCount > 0) prefixBase = (rand()%3);
     ndn::Name preName;
     int additions = 0;
     if(prefixBase == 0){
        additions = (rand()%25)+1;
        preName = ndn::Name("");
     }
     else {
        int base = rand()%preCount;
        preName = ndn::Name(prefixes[base].toUri());
        int components = 0;
        while(additions == 0){
           components = (rand()%25)+1;
           additions = components - (int)preName.size();
        }
        if(additions < 0)
           preName = ndn::Name(prefixes[base].getSubName(0,components).toUri());
     }
     ndn::Block preWire = preName.wireEncode();
     uint8_t *buf = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE/2);
     for(int j = 0; j < additions; j++){
        size_t bsize = mutator.addPrefixCom(preWire, fuzz_seed, buf, preWire.value_size(), PACKETSIZE/2);
        preWire = ndn::Block(buf,bsize);
        preName.wireDecode(preWire);
     }
     prefixes[k] = preName;
     preCount++;
     free(buf);


     int faceChoice = rand()%faceNum;
     while (float(stratUses[faceChoice])>=float(PREFIXES)/float(faceNum))
        faceChoice = rand()%faceNum;

     parameters = ndn::nfd::ControlParameters().setName(prefixes[k]).setFlags(0).setFaceId(256+faceChoice);
     command = make_shared<ndn::nfd::RibRegisterCommand>();
     requestName = command->getRequestName(options.getPrefix(), parameters);
     interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());
     interest.setInterestLifetime(options.getTimeout());
     wire = interest.wireEncode();
     sock.send(boost::asio::buffer(wire.wire(), wire.size()));

     int stratChoice = rand()%stratNum;
     while (float(stratUses[stratChoice])>=float(PREFIXES)/float(stratNum))
            stratChoice = rand()%stratNum;
     stratUses[stratChoice]++;
     parameters = ndn::nfd::ControlParameters().setName(prefixes[k]).setStrategy("ndn:/localhost/nfd/strategy/"+strats[stratChoice]);
     command = make_shared<ndn::nfd::StrategyChoiceSetCommand>();	     
     requestName = command->getRequestName(options.getPrefix(), parameters);
     interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());     
     interest.setInterestLifetime(options.getTimeout());
     wire = interest.wireEncode();
     sock.send(boost::asio::buffer(wire.wire(), wire.size()));
     prefixStrat.insert(std::make_pair(preName.toUri(),strats[stratChoice]));
  }
  
  {
     std::lock_guard<std::mutex> lock(mtx);
     setupComplete = true;
     cvar.notify_all();
  }
  ribThread.join();
  return;
}

//unsigned int fuzz_seed;
#ifdef CUSTOM_MUTATOR
extern "C" size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  static int cpos = 0;
  auto testFlat = flatbuffers::GetMutableRoot<FuzzTrace::Input>(Data);
  seed = Seed;
  size_t dataLen = 0;
  ndn::Interest interest;
  ndn::Data data;
  flatbuffers::FlatBufferBuilder builder(1024);
  uint8_t *flatint = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
  uint8_t *flatdata = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
  try{
     size_t dSize = 1;
     if(Size>1){
        auto fint = testFlat->interest();
        dSize = fint->size();
        std::copy(fint->begin(), fint->end(), flatint);
     }
     ndn::Block wire(flatint, dSize);
     wire.parse();
     try{
        auto fdata = testFlat->data();
	std::copy(fdata->begin(), fdata->end(), flatdata);
        ndn::Block wire1(flatdata, fdata->size());
        wire1.parse();
	data.wireDecode(wire1);
     } 
     catch (boost::exception& e){
        ndn::KeyChain keyChain;
        keyChain.sign(data);
  
     }  
     interest.wireDecode(wire);
  }
  catch (boost::exception& e){
     interest.setName("a/test");
     interest.setCanBePrefix(false);
     const uint8_t bytes[3]={128, 1,255};
     interest.setApplicationParameters(bytes, 3);
     ndn::KeyChain keyChain;
     keyChain.sign(data);
  } 
  
  /*Desigh TODO: Decides whether to always do random changes to potoclos or to choose one of them each mutation
  int protocolChange = (rand()%100);
  if(protocolChange>50){
    //Do random change to protocol to wither face socket or something else
  }*/

  ndn::Block temp(interest.wireEncode());
  int dataCount = mutator.getDataCount();
  int retransmitInterest = (rand()%300)-(300-dataCount);
  if (retransmitInterest > 285){
     int pos = (rand()%dataCount);
     Size = constructInterest(flatint, temp, dataPks[pos], dataSizes[pos]);
  }

  //Choose to respond to previous interest, should we be doing both interest and data or just one?
  int interestCount = mutator.getInterestCount();
  int satisfyInterest = (rand()%1000)-(1000-interestCount);
  if(satisfyInterest > 100 && interestCount > 0){
     int pos = (rand()%interestCount);
     dataLen = DataCustomMutator(data.wireEncode(), interests[pos], dbytes, sizes[pos], MaxSize/2, seed);
     for(size_t i= 0;i<dataLen;i++){
        dataPks[dpos][i] = dbytes[i];
     }
     dataSizes[dpos] = dataLen;
     dpos++;
     if(dpos == 300) 
        dpos = 0;
     if (dataCount != 300)
        mutator.incrementDataCount();
  }
  size_t interestLength = mutator.LLVMFuzzerCustomMutator1(temp, flatint, Size, MaxSize/2, Seed);

  for(size_t i= 0;i<interestLength;i++){
     interests[cpos][i] = flatint[i];
  }
  sizes[cpos] = interestLength;
  cpos++;
  if(cpos == 1000) cpos = 0;
  if (interestCount != 1000)
	  mutator.incrementInterestCount();
  for (size_t i=0; i<dataLen; i++)
     flatdata[i] = dbytes[i];
  std::vector<uint8_t> interestVector(&flatint[0], &flatint[interestLength]);
  std::vector<uint8_t> dataVector(&flatdata[0], &flatdata[dataLen]);
  int face = rand()%faceNum;
  auto inputInterest = builder.CreateVector(interestVector);
  auto inputData = builder.CreateVector(dataVector);
  int prefixId = (rand()%PREFIXES);			 
  auto inputPrefix = builder.CreateString(prefixes[prefixId].toUri());
  auto inputStrategy = builder.CreateString(prefixStrat[prefixes[prefixId].toUri()]);
  auto genInput = FuzzTrace::CreateInput(builder, face,inputInterest, inputData, inputPrefix, inputStrategy);
  builder.Finish(genInput);
  uint8_t *buf = builder.GetBufferPointer();
  int bsize = builder.GetSize();
  for (int i=0; i<bsize; i++)
     Data[i] = buf[i];
  free(flatint);
  free(flatdata);
  return bsize;
}

#endif  // CUSTOM_MUTATOR
size_t DataCustomMutator(ndn::Block temp, uint8_t *inter, uint8_t *Dat, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  ndn::Block wire(inter, Size);
  wire.parse();
  ndn::Data data;
  data.setName("space");
  ndn::KeyChain keyChain;
  keyChain.sign(data);
  size_t totalLength;
  ndn::EncodingEstimator estimator;
  size_t estimatedSize = data.wireEncode(estimator);
  ndn::Block nWire;
  do{ 
     totalLength = 0;
     ndn::EncodingBuffer encoder(estimatedSize, 0);
     for(size_t i=0;i<temp.elements_size();i++){
        if(temp.elements()[i].type()==ndn::tlv::Name)
           totalLength += encoder.appendByteArrayBlock(ndn::tlv::Name, wire.elements()[0].value(), wire.elements()[0].value_size());
        else
           totalLength += encoder.appendByteArrayBlock(temp.elements()[i].type(), temp.elements()[i].value(), temp.elements()[i].value_size());
     }
     totalLength += encoder.prependVarNumber(totalLength);
     totalLength += encoder.prependVarNumber(ndn::tlv::Data);
     nWire = encoder.block();
     if (totalLength>PACKETSIZE){
        temp =  ndn::Block(data.wireEncode());
        temp.parse();
     }
  } while(totalLength>PACKETSIZE);
  
  for(size_t i= 0;i<totalLength;i++){
     Dat[i] = nWire.wire()[i];
  }

  return mutator.LLVMFuzzerCustomMutator1(nWire, Dat, nWire.size(), MaxSize, Seed);
}

