/*
  * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 *  terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
  * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */

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
//#include "ndn-cxx/Mutator.hpp"


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
size_t deleteFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeFHDelTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateName(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeNameComTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateSignatureInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeSigInfoTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateKeyLocator(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateMetaInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize, int ensureSatisfaction);
size_t deleteMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeMetaTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateFinalBlockId(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeAppParamTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
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


