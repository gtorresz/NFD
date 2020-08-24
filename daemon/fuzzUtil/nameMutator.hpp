#ifndef NAME_MUTATOR_HPP
#define NAME_MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
// #include <stdint.h>
// #include <stddef.h>
//
//
namespace ndn {

size_t deleteNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeNameComTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);

size_t deleteNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 1) return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size()+1);
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  for(i=0;i<wire.elements_size();i++){
     if(i>=position && i<(position+deletions) && wire.elements()[i].type()!=2) continue;
     totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes);
  return len;
}

size_t addNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-8) <= (Size))return wire.value_size();

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/3));
  additions = 1;
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  for(i=0;i<wire.elements_size();i++){
     totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<additions;i++){
     totalLength += encoder.appendByteArrayBlock(tlv::GenericNameComponent, bytes, 1);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  encoder.block().parse();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  free(bytes);
  return len;
}

size_t suffleNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(wire.elements_size() <= 1)return wire.value_size();
  wire.parse();
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
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(pos);
  return len;
}

size_t changeNameComTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  size_t component;
  if(wire.elements_size() <= 1) return wire.value_size();
  else {
     do{
        component = (rand()%(wire.elements_size()));
     } while(wire.elements()[component].type()==2);
  }
  for(size_t i=0;i<wire.elements_size();i++){
     if(i == component){
        totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

}
#endif
