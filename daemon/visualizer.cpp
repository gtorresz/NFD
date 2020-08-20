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
#include <ndn-cxx/fuzzer-seed.hpp>
#include "face/pcap-helper.hpp"
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include "fuzzUtil/trace_generated.h"
#include "fuzzUtil/initalization_generated.h"
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
ndn::Name prefixes[PREFIXES];
int seed;
std::vector<std::string> faces = {"/run/nfd.sock","tcp4://0.0.0.0:6363","udp4://0.0.0.0:6363" };
int faceNum = 3;
int faceUses[3] = {0,0,0};
std::vector<std::string> strats = {"best-route","access","asf","multicast","self-learning","ncc"};
int stratNum = 6;
int stratUses[6] = {0,0,0,0,0,0};
std::unordered_map<std::string,std::string> prefixStrat;
std::mutex mtx;
std::mutex NFDmtx;
std::condition_variable cvar;
bool setupComplete = false;
bool NFD_Running = false;

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
  //struct timeval t;
  //t.tv_usec = 1000;
  //1select(0, NULL, NULL, NULL, &t);
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

