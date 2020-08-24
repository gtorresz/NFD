#ifndef MUTATOR_HPP
#define MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
#include "flatbuffers/flatbuffers.h"

namespace ndn {
class Mutator{
public:

Mutator(int IHMS, int DHMS){
   interestHistoryMaxSize = IHMS;
   dataHistoryMaxSize = DHMS;
}

size_t deleteComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t copyCurrentCompnents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleComponents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addrandomTLVComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
uint32_t randomlyChooseField(Block m_wire,unsigned int Seed, int ensureSatisfaction);
size_t mutateNonsubTLVfield(Block wire, uint32_t field, unsigned int Seed, uint8_t* dat, size_t Size, size_t MaxSize);
size_t mutateForwardingHint(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateName(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateSignatureInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateKeyLocator(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateMetaInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize, int ensureSatisfaction);
size_t mutateFinalBlockId(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t computeDigest(Block wire, Block subwire, uint32_t field, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
enum : uint32_t {deletion = 0, addition = 1, suffle = 2, TLVchange = 3, fieldmutation = 4};
Block createField(Block wire, uint32_t field);
size_t LLVMFuzzerCustomMutator1(Block wire, uint8_t *Dat, size_t Size,size_t MaxSize, unsigned int Seed);
uint32_t randomlyChooseSubField(Block m_wire, unsigned int Seed);
size_t addPrefixCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);

size_t getInterestCount(){
   return interestCount;
}

size_t getDataCount(){
	   return dataCount;
}

void incrementDataCount(){
	   dataCount++;
}

int getInterestEndpoint(){
return interestVectorEndpoint;
}

void addToInterestHistory(std::vector<uint8_t>* interest, size_t size){
  if (interestCount <= interestHistoryMaxSize){
     interestCount++;
     interestVector.push_back(std::vector<uint8_t>(interest->begin(), interest->end()));
     interestSizes.push_back(size);
  }
  else {
     interestVector[interestVectorEndpoint] = std::vector<uint8_t>(interest->begin(), interest->end());
     interestSizes[interestVectorEndpoint] = size;
  }

  interestVectorEndpoint++;
  if(interestVectorEndpoint>=interestHistoryMaxSize)
     interestVectorEndpoint=0; 
}

void addToDataHistory(std::vector<uint8_t>* data, size_t size){
  if (dataCount <= dataHistoryMaxSize){
     dataCount++;
     dataVector.push_back(std::vector<uint8_t>(data->begin(), data->end()));
     dataSizes.push_back(size);
  }
  else {
     dataVector[dataVectorEndpoint] = std::vector<uint8_t>(data->begin(), data->end());
     dataSizes[dataVectorEndpoint] = size;
  }

  dataVectorEndpoint++;
  if(dataVectorEndpoint >= dataHistoryMaxSize)
     dataVectorEndpoint=0;
}

void getInterestAt(uint8_t* InterestBytes, int pos){
  interestVector[pos];
  std::copy(interestVector[pos].begin(), interestVector[pos].end(), &InterestBytes[0]);
}

void getDataAt(uint8_t* DataBytes, int pos){
  dataVector[pos];
  std::copy(dataVector[pos].begin(), dataVector[pos].end(), &DataBytes[0]);
}

size_t getInterestSize(int pos){
return interestSizes[pos] ;
}

size_t getDataSize(int pos){
   return dataSizes[pos] ;
}

private:
int interestCount = 0;
int dataCount = 0;
int interestVectorEndpoint = 0;
int dataVectorEndpoint = 0;
int interestHistoryMaxSize;
int dataHistoryMaxSize;
std::vector<std::vector<uint8_t>> interestVector;
std::vector<size_t> interestSizes;
std::vector<std::vector<uint8_t>> dataVector;
std::vector<size_t> dataSizes;
};

} // namespace ndn
#endif  // CUSTOM_MUTATOR


