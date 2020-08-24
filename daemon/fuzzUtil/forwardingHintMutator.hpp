#ifndef FORWARDER_HINT_MUTATOR_HPP
#define FORWARDER_HINT_MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {

size_t deleteFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeFHDelTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);

size_t deleteFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size());
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  size_t i;

  for(i=0;i<wire.elements_size();i++){
     if(i>=position && i<(position+deletions))
        continue;
     totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t addFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-10) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/10));

  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t bytes1[3] = {8,1, 255};
  uint8_t bytes2[1] = {255};

  size_t i;

  for(i=0;i<wire.elements_size();i++){
     totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<additions;i++){
     size_t delLen = 0;

     delLen += encoder.prependByteArrayBlock(tlv::Name,  bytes1, 3);
     delLen += encoder.prependByteArrayBlock(tlv::LinkPreference,  bytes2, 1);

     delLen += encoder.prependVarNumber(delLen);
     delLen += encoder.prependVarNumber(tlv::LinkDelegation);
     totalLength += delLen;
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t suffleFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() == 1)return wire.value_size();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;
  }

  suffleIndex = 0;
  while(suffleIndex<suffles){
     uint32_t temp;
     int first = (rand()%(wire.elements_size()));
     int second = (rand()%(wire.elements_size()));
     temp = pos[first];
     pos[first]=pos[second];
     pos[second] = temp;
     suffleIndex++;
 }

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::LinkDelegation);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(pos);
  return len;
}

size_t changeFHDelTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
   if((MaxSize-5) <= (Size))return wire.value_size();
   size_t totalLength = 0;
   EncodingEstimator estimator;
   Name name;
   wire.parse();
   size_t estimatedSize = name.wireEncode(estimator);

   EncodingBuffer encoder(estimatedSize, 0);
   uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
   bytes[0] = 255;

   uint64_t newTLV = (rand()%(std::numeric_limits<uint64_t>::max()));
   size_t component = (rand()%(wire.elements_size()));

   for(size_t i=0;i<wire.elements_size();i++){
      if(i == component){
         size_t delLen = 0;
	 size_t dels = wire.elements()[i].elements_size();
	 delLen += encoder.prependByteArrayBlock(newTLV,  bytes, 1);
	 for(size_t k = 1; k<=dels;k++){
            delLen += encoder.prependByteArrayBlock(wire.elements()[i].elements()[dels-k].type(), wire.elements()[i].elements()[dels-k].value(), wire.elements()[i].elements()[dels-k].value_size());
	 }
	 delLen += encoder.prependVarNumber(delLen);
	 delLen += encoder.prependVarNumber(tlv::LinkDelegation);
	 totalLength += delLen;
      }
      else
         totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
   }

   totalLength += encoder.prependVarNumber(totalLength);
   totalLength += encoder.prependVarNumber(tlv::LinkDelegation);
   size_t len = encoder.block().value_size();
   const uint8_t* byteTransfer = encoder.block().value();
   for(size_t i = 0; i < len; i++){
      Dat[i]= byteTransfer[i];
   }

   free(bytes);
   return len;
}

}
#endif
