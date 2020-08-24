#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include "fuzzUtil/trace_generated.h"
#include "fuzzUtil/initalization_generated.h"
#include "fuzzUtil/nfd_runner.hpp"

//namespace po = boost::program_options;

size_t DataCustomMutator(ndn::Block temp, uint8_t *inter, uint8_t *Dat, size_t Size,
                                          size_t MaxSize, unsigned int Seed);
int *k;
char fr[100000];
char ***c;
ndn::Mutator mutator(INT_HIST_SIZE, DAT_HIST_SIZE);
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



std::mutex seedMtx;

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
  flatbuffers::FlatBufferBuilder builder(1024);
  std::vector<std::string> prefixTrace; 
  std::vector<std::string> stratTrace;
  std::vector<int> faceTrace;
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
     prefixTrace.push_back(preName.toUri());
     preCount++;
     free(buf);


     int faceChoice = rand()%faceNum;
     while (float(stratUses[faceChoice])>=float(PREFIXES)/float(faceNum))
        faceChoice = rand()%faceNum;
     faceTrace.push_back(faceChoice);
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
     stratTrace.push_back(strats[stratChoice]);
     parameters = ndn::nfd::ControlParameters().setName(prefixes[k]).setStrategy("ndn:/localhost/nfd/strategy/"+strats[stratChoice]);
     command = make_shared<ndn::nfd::StrategyChoiceSetCommand>();	     
     requestName = command->getRequestName(options.getPrefix(), parameters);
     interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());     
     interest.setInterestLifetime(options.getTimeout());
     wire = interest.wireEncode();
     sock.send(boost::asio::buffer(wire.wire(), wire.size()));
     prefixStrat.insert(std::make_pair(preName.toUri(),strats[stratChoice]));
  }
  
  auto initialPrefix = builder.CreateVectorOfStrings(prefixTrace);
  auto initialStrat = builder.CreateVectorOfStrings(stratTrace);
  auto initialFace = builder.CreateVector(faceTrace);
  auto genInitial = FuzzTrace::CreateInitial(builder, fuzz_seed, initialPrefix, initialFace, initialStrat);
  builder.Finish(genInitial);
  uint8_t *buf = builder.GetBufferPointer();
  int bsize = builder.GetSize();

  for(int i = 0;i<bsize; i++)
     fprintf(fp,"%02x", buf[i]);
  fprintf(fp, "\n");
  fclose(fp);

  {
     std::lock_guard<std::mutex> lock(mtx);
     setupComplete = true;
     cvar.notify_all();
  }
  ribThread.join();
  return;
}

//#ifdef CUSTOM_MUTATOR
extern "C" size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
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
  
  /*Desigh TODO: Decides whether to always do random changes to protocol or to choose one of them each mutation
  int protocolChange = (rand()%100);
  if(protocolChange>50){
    //Do random change to protocol to wither face socket or something else
  }*/

  ndn::Block temp(interest.wireEncode());
  int dataCount = mutator.getDataCount();
  int retransmitInterest = (rand()%DAT_HIST_SIZE)-(DAT_HIST_SIZE-dataCount);
  if (retransmitInterest > 200){
     int pos = (rand()%dataCount);
     uint8_t *prevData = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);
     mutator.getDataAt(prevData, pos);
     Size = constructInterest(flatint, temp, prevData, mutator.getDataSize(pos));
     free(prevData);
  }

  //Choose to respond to previous interest, should we be doing both interest and data or just one?
  int interestCount = mutator.getInterestCount();
  int satisfyInterest = (rand()%INT_HIST_SIZE)-(INT_HIST_SIZE-interestCount);
  if(satisfyInterest > 100 && interestCount > 0){
     int pos = (rand()%interestCount);
     uint8_t *prevInt = ( uint8_t*) malloc(sizeof(uint8_t)*PACKETSIZE);   
     mutator.getInterestAt(prevInt, pos);
     dataLen = DataCustomMutator(data.wireEncode(), prevInt, flatdata, mutator.getInterestSize(pos), PACKETSIZE, seed);
     free(prevInt);
     std::vector<uint8_t> dataSent(&flatdata[0], &flatdata[dataLen]);
     mutator.addToDataHistory(&dataSent, dataLen);

  }
  size_t interestLength = mutator.LLVMFuzzerCustomMutator1(temp, flatint, Size, PACKETSIZE, Seed);

  std::vector<uint8_t> interestVector(&flatint[0], &flatint[interestLength]);
  std::vector<uint8_t> dataVector(&flatdata[0], &flatdata[dataLen]);
  mutator.addToInterestHistory(&interestVector, interestLength);
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
  if(size_t(bsize)>MaxSize){
     free(flatint);
     free(flatdata);
     return Size;
  }
  for (int i=0; i<bsize; i++)
     Data[i] = buf[i];
  free(flatint);
  free(flatdata);
  return bsize;
}

//#endif  // CUSTOM_MUTATOR
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
        if(temp.elements()[i].type()==ndn::tlv::Name){
           totalLength += encoder.appendByteArrayBlock(ndn::tlv::Name, wire.elements()[0].value(), wire.elements()[0].value_size());
	}
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

