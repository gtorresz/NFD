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
#include <ndn-cxx/mutator.hpp>
#include <ndn-cxx/fuzzer-seed.hpp>
#include "face/pcap-helper.hpp"
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include "fuzzer/trace_generated.h"
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
  run()
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
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
   k = argc;
   c = argv;
   return 0;
}

size_t constructInterest(uint8_t *sendBytes, ndn::Block inter, uint8_t* Dat, size_t Size){
   ndn::Interest interest;
   size_t totalLength = 0;
   ndn::EncodingEstimator estimator;
   interest.wireDecode(inter);
//   interest.setName("temp");
//   interest.setCanBePrefix(false);
//   const uint8_t bytes[3]={128, 1,255};
//   interest.setApplicationParameters(bytes, 3);
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


uint8_t interests[1000][PACKETSIZE];
uint8_t dataPks[300][PACKETSIZE];
uint8_t dbytes[PACKETSIZE];
ndn::Name prefixes[PREFIXES];
int preCount = 0;
//size_t dataLen;
int size = 0;
int dataSize = 0;
size_t sizes[1000];
size_t dataSizes[1000];
int seed;
int dpos =0;
std::vector<std::string> faces = {"/run/nfd.sock"};
extern "C" int 
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
//static int cpos = 0;
 using namespace nfd;
 if(Size <= 2 )return 0;
 boost::asio::local::stream_protocol::socket* s;
 int socky = 0;//Data[0];
// Data++;
// Size--;
 if(Size <= 2 )return 0;

 uint8_t *buf = ( uint8_t*) malloc(sizeof(uint8_t)*Size);
  std::copy(&Data[0], &Data[Size], &buf[0]);
 auto flatData = flatbuffers::GetRoot<FuzzTrace::Input>(buf);
 uint8_t *flatint = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
 uint8_t *flatdata = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
 auto testf = flatData->prefix()->str();
// std::cout<<"hello "<<testf<<std::endl;
 auto fint = flatData->interest();
 std::copy(fint->begin(), fint->end(), &flatint[0]);
 auto fdata = flatData->data();
 std::copy(fdata->begin(), fdata->end(), flatdata);
 //   ndn::Block wireInt(Data, Size);
   ndn::Block wireInt(flatint,fint->size());
   wireInt.parse();

  Interest inte("hu/what");
   inte.setCanBePrefix(true);
   Block wire = inte.wireEncode();
  FILE* fp = fopen (fr, "a");
//  fprintf(fp, "interest,%d,",socky);
inte.wireDecode(wireInt);
inte.setName(ndn::Name(testf+inte.getName().toUri()));
wireInt = inte.wireEncode();
inte.wireDecode(wireInt);
if(socky==0){
//std::cout<<"sock\n";
 s = &sock;
}
else if(socky==1){
//std::cout<<"sock1\n";
 s = &sock1;
}
else {
//std::cout<<"sock2\n";
 s = &sock2;
}
 s->send(boost::asio::buffer(wireInt.wire(), wireInt.size()));
 const uint8_t* writeBytes = wireInt.wire();
// for(size_t i = 0;i<wireInt.size(); i++)
//    fprintf(fp,"%02x", writeBytes[i]);
// fprintf(fp, "\n");
//  fclose(fp);
// if(Size!=wireInt.size()){
if(fdata->size()!=0){
//std::cout<<"Doing it\n";
  //  ndn::Block wire1(Data+wireInt.size(), Size-wireInt.size());
    ndn::Block wire1(flatdata,fdata->size());
    wire1.parse();
//    fp = fopen (fr, "a");
//    fprintf(fp, "data,%d,",socky);
    writeBytes = wire1.wire();
//    for(size_t i = 0;i<wire1.size(); i++)
//       fprintf(fp,"%02x", writeBytes[i]);
//    fprintf(fp, "\n");
//    fclose(fp);
     s->send(boost::asio::buffer(wire1.wire(), wire1.size()));
 }
for(size_t i = 0;i<Size; i++)
       fprintf(fp,"%02x", Data[i]);
           fprintf(fp, "\n");
	       fclose(fp);
free(flatdata);
free(flatint);
free(buf);
  return 0;//runner.run();
}

extern "C" void
SetUp(){
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  std::clock_t start;
  start = std::clock();
  timeinfo = localtime (&rawtime);
  sprintf(fr, "FuzzerTrace/packetTrace.csv");//,asctime(timeinfo) );
  using namespace nfd;
  FILE* fp = fopen (fr, "w");
  fprintf(fp, "packetType,face,bytes\n");
  fclose(fp);
  std::string configFile = DEFAULT_CONFIG_FILE;
  NfdRunner runner(configFile);
  std::thread ribThread([&runner]/*[configFile]*/{//, &wire] {
  //NfdRunner runner(configFile);
  runner.initialize();
  return runner.run();
   });
  struct timeval t;
  t.tv_sec = 1;
  t.tv_usec = 500000;
  select(0, NULL, NULL, NULL, &t);
  ep = boost::asio::local::stream_protocol::endpoint("/0.0.0.0:6363");
  //delay(1000);
  int i = 0;
  int k = 0;
  while(i <100000){
	   while(k <100000){
    double sy = 1200;
   double sx = 1200;
    sx = sy*sx;
	  k++; }i++;
  }
  usleep(5000000);
  sock.connect(ep);
  sock1.connect(ep);
  sock2.connect(ep);
  ndn::nfd::CommandOptions options;
  ndn::security::SigningInfo signingInfo;
  options.setSigningInfo(signingInfo);
  ControlParameters parameters = ndn::nfd::ControlParameters().setName("/a").setFlags(0);
   shared_ptr<ControlCommand> command = make_shared<ndn::nfd::RibRegisterCommand>();
  Name requestName = command->getRequestName(options.getPrefix(), parameters);
  ndn::KeyChain keyChain;
  ndn::security::CommandInterestSigner m_signer(keyChain);
  Interest interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());
  interest.setInterestLifetime(options.getTimeout());
  ndn::Block wire = interest.wireEncode();
  sock.send(boost::asio::buffer(wire.wire(), wire.size()));


  ControlParameters parameters1 = ndn::nfd::ControlParameters().setName("/b").setFlags(0);
  shared_ptr<ControlCommand> command1 = make_shared<ndn::nfd::RibRegisterCommand>();
  Name requestName1 = command1->getRequestName(options.getPrefix(), parameters1);
  ndn::KeyChain keyChain1;
  ndn::security::CommandInterestSigner m_signer1(keyChain1);
  Interest interest1 = m_signer1.makeCommandInterest(requestName1, options.getSigningInfo());
  interest1.setInterestLifetime(options.getTimeout());
  ndn::Block wire1 = interest1.wireEncode();
  sock.send(boost::asio::buffer(wire1.wire(), wire1.size()));


  /*ControlParameters parameters2 = ndn::nfd::ControlParameters().setName("/c").setFlags(0);
  shared_ptr<ControlCommand> command2 = make_shared<ndn::nfd::RibRegisterCommand>();
  Name requestName2 = command2->getRequestName(options.getPrefix(), parameters2);
  ndn::KeyChain keyChain2;
  ndn::security::CommandInterestSigner m_signer2(keyChain2);
  Interest interest2 = m_signer2.makeCommandInterest(requestName2, options.getSigningInfo());
  interest2.setInterestLifetime(options.getTimeout());
  ndn::Block wire2 = interest2.wireEncode();
  sock.send(boost::asio::buffer(wire2.wire(), wire2.size()));
*/
  //create prefixes TODO
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
        size_t bsize = addPrefixCom(preWire, fuzz_seed, buf, preWire.value_size(), PACKETSIZE/2);
        preWire = ndn::Block(buf,bsize);
        preName.wireDecode(preWire);
     }
    // std::cout<<"Testing... "<<preName<<std::endl;
     prefixes[k] = preName;
     preCount++;
     free(buf);
     //runner.addFibentry(prefixes[k]);
       ControlParameters parameters2 = ndn::nfd::ControlParameters().setName(prefixes[k]).setFlags(0);
         shared_ptr<ControlCommand> command2 = make_shared<ndn::nfd::RibRegisterCommand>();
	   Name requestName2 = command2->getRequestName(options.getPrefix(), parameters2);
	     ndn::KeyChain keyChain2;
	       ndn::security::CommandInterestSigner m_signer2(keyChain2);
	         Interest interest2 = m_signer2.makeCommandInterest(requestName2, options.getSigningInfo());
		   interest2.setInterestLifetime(options.getTimeout());
		     ndn::Block wire2 = interest2.wireEncode();
		       sock.send(boost::asio::buffer(wire2.wire(), wire2.size()));
  }
  for(int k = 0; k < PREFIXES; k++){
   //  std::cout<<"Verifing... "<<prefixes[k]<<std::endl;
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
//std::cout<<testFlat->mutable_face()<<std::endl;
 seed = Seed;
 fuzz_seed = Seed;
 size_t dataLen = 0;
 ndn::Interest interest;
 ndn::Data data;
 flatbuffers::FlatBufferBuilder builder(1024);
 uint8_t *flatint = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);//[fint->size()];
 uint8_t *flatdata = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
 try{
    size_t dSize = 1;
    if(Size>1){
    auto fint = testFlat->interest();
     dSize = fint->size();
     std::copy(fint->begin(), fint->end(), flatint);
    }
    //ndn::Block wire(Data+1, Size);
    //wire.parse();
    ndn::Block wire(flatint, dSize);
    wire.parse();
       try{
          auto fdata = testFlat->data();
	  std::copy(fdata->begin(), fdata->end(), flatdata);
	  //ndn::Block wire1(Data+wire.size()+1, Size-wire.size());
          //wire1.parse();
          //data.wireDecode(wire1);
	  //std::cout<<"Name Test: original "<<data.getName()<<std::endl;
          ndn::Block wire1(flatdata, fdata->size());
          wire1.parse();
	  data.wireDecode(wire1);
	  //std::cout<<"Name Test: flat "<<data.getName()<<std::endl;
     } 
       catch (boost::exception& e){
          ndn::KeyChain keyChain;
          keyChain.sign(data);
  
    }

    //interest.wireDecode(wire);
    //std::cout<<"Name Test interest: original "<<interest.getName()<<std::endl;
    interest.wireDecode(wire);
    //std::cout<<"Name Test interest: flat "<<interest.getName()<<std::endl;
  }
   catch (boost::exception& e){
     interest.setName("a/test");
     interest.setCanBePrefix(false);
     const uint8_t bytes[3]={128, 1,255};
     interest.setApplicationParameters(bytes, 3);
     ndn::KeyChain keyChain;
     keyChain.sign(data);
   } 
  int protocolChange = (rand()%100);
  if(protocolChange>50){
    //Do random change to protocol to wither face socket or something else
  }
  ndn::Block temp(interest.wireEncode());

 int retransmitInterest = (rand()%300)-(300-dataSize);
 if (retransmitInterest > 285){
    int pos = (rand()%dataSize);
    //Size = constructInterest(Data+1,temp, dataPks[pos], dataSizes[pos]);
    Size = constructInterest(flatint, temp, dataPks[pos], dataSizes[pos]);
 }

 //Choose to respond to previous interest, should we be doing both interest and data or just one?
  int satisfyInterest = (rand()%1000)-(1000-size);
  if(satisfyInterest > 100 && size > 0){
     int pos = (rand()%size);
     dataLen = DataCustomMutator(data.wireEncode(), interests[pos], dbytes, sizes[pos], MaxSize/2, seed);
     for(size_t i= 0;i<dataLen;i++){
     dataPks[dpos][i] = dbytes[i];
    }
    dataSizes[dpos] = dataLen;
    dpos++;
    if(dpos == 300) dpos = 0;
    if (dataSize != 300)dataSize++;
  }
  size_t interestLength = LLVMFuzzerCustomMutator1(temp, flatint, Size, MaxSize/2, Seed);

   //int socky = rand()%3;
   //Data[0] = socky;
   //Data++;
   for(size_t i= 0;i<interestLength;i++){
//   interests[cpos][i] = Data[i];
   interests[cpos][i] = flatint[i];
   }
  sizes[cpos] = interestLength;
  cpos++;
  if(cpos == 1000) cpos = 0;
  if (size != 1000)size++;
  for (size_t i=0; i<dataLen; i++)
     //Data[i+interestLength] = dbytes[i];
     flatdata[i] = dbytes[i];
  //std::vector<uint8_t> interestVector(&interests[cpos-1][0], &interests[cpos-1][interestLength]);
  //std::vector<uint8_t> dataVector(&dbytes[0], &dbytes[dataLen]);
  std::vector<uint8_t> interestVector(&flatint[0], &flatint[interestLength]);
  std::vector<uint8_t> dataVector(&flatdata[0], &flatdata[dataLen]);
  //for(size_t i= 0;i<interestLength;i++){
  // printf("Original %x\n",Data[i]);
  // printf("Copy %x\n",interestVector[i]);
  //}
  auto face = builder.CreateString("Test");
  auto inputInterest = builder.CreateVector(interestVector);
  auto inputData = builder.CreateVector(dataVector);
  int prefixId = (rand()%PREFIXES);			 
  auto inputPrefix = builder.CreateString(prefixes[prefixId].toUri());
  auto genInput = FuzzTrace::CreateInput(builder, face,inputInterest, inputData, inputPrefix);
  builder.Finish(genInput);
  uint8_t *buf = builder.GetBufferPointer();
  int bsize = builder.GetSize();
//  std::cout<<"Compare the sizes boi: Interest+Data "<<interestLength+dataLen<<"  flatbuffer "<<bsize<<std::endl;
  for (int i=0; i<bsize; i++)
    Data[i] = buf[i];
  free(flatint);
  free(flatdata);
  return bsize;
}

#endif  // CUSTOM_MUTATOR
size_t DataCustomMutator(ndn::Block temp, uint8_t *inter, uint8_t *Dat, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
// ndn::Interest interest;
// try{
   ndn::Block wire(inter, Size);
   wire.parse();
//   ndn::Name name;
//   name.wireDecode(wire.elements()[0]);
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
  }while(totalLength>PACKETSIZE);
  
   for(size_t i= 0;i<totalLength;i++){
        Dat[i] = nWire.wire()[i];
     }

  return LLVMFuzzerCustomMutator1(nWire, Dat, nWire.size(), MaxSize, Seed);
}

