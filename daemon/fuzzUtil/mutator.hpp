#ifndef MUTATOR_HPP
#define MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
#include <stdint.h>
#include <stddef.h>


namespace ndn {
class Mutator{
 public:
 Mutator(){
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

void incrementInterestCount(){
   interestCount++;
}

size_t getDataCount(){
	   return dataCount;
}

void incrementDataCount(){
	   dataCount++;
}
private:
int interestCount = 0;
int dataCount = 0;
};

} // namespace ndn
#endif  // CUSTOM_MUTATOR


