#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
#include <stdint.h>
#include <stddef.h>
#include "mutator.hpp"
#include "mutator-modules/nameMutator.hpp"
#include "mutator-modules/forwardingHintMutator.hpp"
#include "mutator-modules/signatureInfoMutator.hpp"
#include "mutator-modules/appParameterMutator.hpp"
#include "mutator-modules/metaInfoMutator.hpp"


namespace ndn {
extern "C" size_t
LLVMFuzzerMutate(uint8_t *Dat, size_t Size, size_t MaxSize);

size_t Mutator::LLVMFuzzerCustomMutator1(Block wire, uint8_t *Dat, size_t Size,
		                                          size_t MaxSize, unsigned int Seed){
  srand (Seed);
  uint32_t mutationType = (rand()%5);
  mutationType = Mutator::fieldmutation;
  if(mutationType != Mutator::fieldmutation){
     switch(mutationType){
        case Mutator::deletion :
           return deleteComponent(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::addition :
           return copyCurrentCompnents(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::suffle :
           return suffleComponents(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::TLVchange :
           return addrandomTLVComponent(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  int ensureSatisfaction = rand()%100;
  uint32_t field = randomlyChooseField(wire, Seed, ensureSatisfaction);
  wire.parse();
  Block::element_const_iterator element = wire.find(field);

  if (element == wire.elements_end()){
      wire = createField(wire, field);
      wire.parse();
      element = wire.find(field);
  }
  Block subwire = *element;

  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  size_t len;
  const uint8_t* loopwire = element->value();
  for(i = 0; i < element->value_size(); i++){
     bytes1[i] = loopwire[i];
  }

  if (field ==  tlv::Name){
     len = mutateName(subwire, Seed, bytes1,Size, MaxSize);
  }
  else if(field == tlv::ForwardingHint){
     len = mutateForwardingHint(subwire, Seed, bytes1,Size, MaxSize);
  }
  else if(field == tlv::SignatureInfo){
     len = mutateSignatureInfo(subwire, Seed, bytes1,Size, MaxSize);
  }
  else if(field == tlv::MetaInfo){
     len = mutateMetaInfo(subwire, Seed, bytes1,Size, MaxSize, ensureSatisfaction);
  }
  else if(field == tlv::ApplicationParameters){
     len = mutateAppParam(subwire, Seed, bytes1,Size, MaxSize);
  }
  else{
     len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
  }
  element = wire.elements_end();
  size_t totalLength = 0;
  element--;
  EncodingEstimator estimator;
  size_t estimatedSize;
  if (wire.type() == tlv::Interest){
     Interest interest;
     interest.setCanBePrefix(false);
     estimatedSize = interest.wireEncode(estimator);
  }
  else{
     Data data;
     KeyChain keyChain;
     keyChain.sign(data);
     estimatedSize = data.wireEncode(estimator); 
  }
  EncodingBuffer encoder(estimatedSize, 0);

  for(size_t i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type()){
        if(len == 0 )continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }
     else if(field == tlv::ApplicationParameters && wire.elements()[i].type() == tlv::Name){
         EncodingBuffer tempEncoder(estimatedSize, 0);
         size_t Length = tempEncoder.prependByteArray(bytes1, len);
         Length += tempEncoder.prependVarNumber(len);
         Length += tempEncoder.prependVarNumber(tlv::ApplicationParameters);
         uint8_t* digest = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
         size_t namelen = computeDigest(wire.elements()[i], tempEncoder.block(), field, Seed, digest, Size, MaxSize);

         totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), digest, namelen);
         free(digest);
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(wire.type());
  const uint8_t* bytes2 = encoder.block().wire();
  free(bytes1);
  if(encoder.block().size()>MaxSize) return Size;

  for(size_t j = 0; j < encoder.block().size(); j++){
     Dat[j] = bytes2[j];
  }

   return encoder.block().size();
}


size_t Mutator::deleteComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(wire.elements_size() < 2)return wire.size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Interest interest;
  wire.parse();
  size_t estimatedSize = interest.wireEncode(estimator);
  uint32_t position = 1+(rand()%(wire.elements_size()-2));
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  for(i=0;i<wire.elements_size();i++){
        if(i==position) continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(i = 0; i < len; i++){
     Dat[i]= loopwire[i];
     }
  free(bytes); 
  return len;
}


size_t Mutator::computeDigest(Block wire, Block subwire, uint32_t field, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(size_t i=0;i<wire.elements_size();i++){
     if(field == tlv::ApplicationParameters && wire.elements()[i].type() == tlv::ParametersSha256DigestComponent){
         if(subwire.value_size() == 0 )continue;
         using namespace security::transform;
         StepSource in;
         OBufferStream out;
         in >> digestFilter(DigestAlgorithm::SHA256) >> streamSink(out);
         subwire.parse();
            in.write(subwire.wire(), subwire.size());
         in.end();
          out.buf();
         auto digestComponent = name::Component::fromParametersSha256Digest(out.buf());
         Block wi = digestComponent.wireEncode();
         totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wi.value(), wi.value_size());
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* loopwire = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= loopwire[i];
  }

  return len;
}

size_t Mutator::addrandomTLVComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-5) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  for(size_t i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.appendByteArrayBlock(newTLV,  bytes, 1);
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(size_t i = 0; i < len; i++){
     Dat[i]= loopwire[i];
  }

  free(bytes);
  return len;
}

size_t Mutator::copyCurrentCompnents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(MaxSize <= Size*2)return wire.size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Interest interest;
  wire.parse();
  size_t estimatedSize = interest.wireEncode(estimator);
  EncodingBuffer encoder(estimatedSize, 0);

  size_t i;

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(i = 0; i < len; i++){
     Dat[i]= loopwire[i];
     }

  return len;
}

size_t Mutator::suffleComponents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
return 0;
}

uint32_t Mutator::randomlyChooseField(Block m_wire, unsigned int Seed, int ensureSatisfaction){
  int ele;
  if(m_wire.type() == tlv::Data){
     if(ensureSatisfaction > 10)
        ele = (rand()%5);
     else 
        ele = 1+(rand()%4);
     uint32_t array [5]= {7,20,21,22,23};
     return array[ele];}
  ele = (rand()%5);
  uint32_t array [8]= {7,30,10,12,34,36};
  return array[ele];
}

uint32_t Mutator::randomlyChooseSubField(Block m_wire, unsigned int Seed){
  int ele;
  m_wire.parse();
  uint32_t sigInfoFields [7]= {tlv::SignatureType, tlv::KeyLocator, tlv::AdditionalDescription, tlv::DescriptionEntry, tlv::DescriptionKey, tlv::DescriptionValue, tlv::ValidityPeriod} ;
  uint32_t metaInfoFields [3]={tlv::ContentType, tlv::FreshnessPeriod, tlv::FinalBlockId};
  if(m_wire.type() == tlv::SignatureInfo){
     ele = (rand()%6);
     return sigInfoFields[ele];  
  }
  else if(m_wire.type() == tlv::MetaInfo){
     ele = (rand()%3);
     return metaInfoFields[ele];
  }
  else{
     if(m_wire.elements_size()<=1) return 0;
     else {
        ele = (rand()%m_wire.elements_size());
        return ele;
     }
  }
}

size_t Mutator::mutateNonsubTLVfield(Block wire, uint32_t field, unsigned int Seed, uint8_t* dat, size_t Size, size_t MaxSize){
  wire.parse();
  Block::element_const_iterator element = wire.find(field);
  if (field == tlv::ContentType)field = tlv::SignatureType;
  if (field == tlv::FreshnessPeriod || field == tlv::LinkPreference)field = tlv::InterestLifetime;
  size_t len;
  do {
        if (field == tlv::InterestLifetime || field == tlv::SignatureType || field == tlv::Nonce)len = LLVMFuzzerMutate(dat,element->value_size(),8);
        else if(field == tlv::HopLimit) len = LLVMFuzzerMutate(dat,element->value_size(),1); 
        else{
           size_t freespace = MaxSize-Size-8;
         if(MaxSize <= Size+8)
              freespace = 0;
           len = LLVMFuzzerMutate(dat,element->value_size(),freespace+element->value_size());
      }
  }while((field == tlv::SignatureType  && len != 1 && len != 2)||(field == tlv::InterestLifetime && len != 1 && len != 2  && len != 4  && len != 8 )|| (field == tlv::Nonce && len != 4));
   return len;
}


Block Mutator::createField(Block wire, uint32_t field ){
  if(wire.type()==tlv::Interest){
     Interest interest;
     interest.wireDecode(wire);
     DelegationList del;
     Name hname("test");
     switch(field) {
      case tlv::Nonce :
        interest.setNonce(0);
        break;
      case tlv::InterestLifetime : 
	interest.setInterestLifetime(2_s);
	break;
      case tlv::ForwardingHint :
        del.insert(64, hname, DelegationList::INS_APPEND);
        interest.setForwardingHint(del);
        break;
      case tlv::HopLimit :
         interest.setHopLimit(0);
         break;
      case tlv::ApplicationParameters :
         const uint8_t bytes[3]={128, 1,255};
         interest.setApplicationParameters(bytes, 3);
         break;
     }
     return interest.wireEncode();
  }
  else if(wire.type()==tlv::Data){
     Data data;
     data.wireDecode(wire);
     const uint8_t bytes[1]={255};
     switch(field) {
      case tlv::MetaInfo :
        data.setMetaInfo(MetaInfo());
        break;
      case tlv::Content :
        data.setContent(bytes, 1);
        break;
      case tlv::SignatureInfo : case tlv::SignatureValue :
        data.setSignature(Signature());
        break;
     }
     return data.wireEncode();
  }
  else if(wire.type()==tlv::SignatureInfo){
     SignatureInfo sig; 
     sig.wireDecode(wire);
     if (field == tlv::KeyLocator){
        KeyLocator kl("T");
        sig.setKeyLocator(kl);
     }
     else if(field == tlv::ValidityPeriod){
        const time::system_clock::TimePoint notb = time::fromIsoString("1400.10");
        const time::system_clock::TimePoint nota = time::fromIsoString("1400.10");
        security::ValidityPeriod vp(notb, nota);
        sig.setValidityPeriod(vp);
     }
     else {
        uint8_t byte[3]={static_cast<uint8_t>(field), 1, 255};
        Block block(byte,3);        
        sig.appendTypeSpecificTlv(block);
     }
     return sig.wireEncode();
  }
  else {
     MetaInfo mInfo;
     mInfo.wireDecode(wire);
     if(field == tlv::ContentType){
        mInfo.setType(1);  
     }
     else if(field == tlv::FreshnessPeriod){
        mInfo.setFreshnessPeriod(2_s);
     }
     else{
        mInfo.setFinalBlock(name::Component("A"));
     }
     return mInfo.wireEncode(); 
  }
}

size_t Mutator::mutateForwardingHint(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
  if(mutationType != Mutator::fieldmutation){
     switch(mutationType){
        case Mutator::deletion :
           return deleteFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::addition :
           return addFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::suffle :
           return suffleFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::TLVchange :
           return changeFHDelTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  uint32_t field = randomlyChooseSubField(wire, Seed);
 size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  wire.parse();
  Block subwire = wire.elements()[field];
  int ele = (rand()%2);
  subwire.elements()[ele];
  const uint8_t* byteTransfer = subwire.elements()[ele].value();
  for(i = 0; i < subwire.elements()[ele].value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }

  if(subwire.elements()[ele].type() == tlv::Name){
     len =  mutateName(subwire.elements()[ele], Seed, bytes1, Size, MaxSize);
  }
  else{
     size_t freespace = MaxSize-Size-8;
     if(MaxSize <= Size+8)
        freespace = 0;
     len =  mutateNonsubTLVfield(subwire, subwire.elements()[ele].type(), Seed, bytes1, Size, MaxSize);

  }
  size_t totalLength = 0;

  EncodingEstimator estimator;
  Name del;
  size_t estimatedSize = del.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  for(i=1;i<=wire.elements_size();i++){
     subwire = wire.elements()[wire.elements_size()-i];
     size_t delLen = 0;
     if(field == wire.elements_size()-i && ele == 1){
        delLen += encoder.prependByteArrayBlock(subwire.elements()[1].type(),  bytes1, len);
      }
      else{
        delLen += encoder.prependByteArrayBlock(subwire.elements()[1].type(), subwire.elements()[1].value(), subwire.elements()[1].value_size());
      }
      if(field == wire.elements_size()-i && ele == 0){
                delLen += encoder.prependByteArrayBlock(subwire.elements()[0].type(),  bytes1, len);

    }
      else {
           delLen += encoder.prependByteArrayBlock(subwire.elements()[0].type(), subwire.elements()[0].value(), subwire.elements()[0].value_size());
      }
      delLen += encoder.prependVarNumber(delLen);
      delLen += encoder.prependVarNumber(tlv::LinkDelegation);
      totalLength += delLen;
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++)
     Dat[i]= byteTransfer[i];
  free(bytes1);
  return len;
}


size_t Mutator::mutateName(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
  if(mutationType < TLVchange){
     switch(mutationType){
        case deletion :
         return deleteNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return addNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleNameCom(wire, Seed, Dat, Size, MaxSize); 
           break;
        case TLVchange :
           return changeNameComTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  if (wire.elements_size() == 0 ) return wire.value_size();
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  wire.parse();
   
  const uint8_t* byteTransfer = wire.elements()[field].value();
  for(i = 0; i < wire.elements()[field].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  size_t freespace = MaxSize - Size -8;
     if(MaxSize <= Size+8)
        freespace = 0;
  len =  LLVMFuzzerMutate(bytes1, wire.elements()[field].value_size(),freespace+wire.elements()[field].value_size());

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){  
     if(field == i)
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes1);
  return len;

}


size_t Mutator::addPrefixCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
   if((MaxSize-8) <= (Size))return wire.value_size();

   size_t totalLength = 0;
   EncodingEstimator estimator;
   Name name;
   wire.parse();
   size_t estimatedSize = name.wireEncode(estimator);
   uint32_t additions = (rand()%((MaxSize-Size)/3));
   additions = 1;
   EncodingBuffer encoder(estimatedSize, 0);
   uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
   bytes[0] = 255;
   size_t len = 1;
   uint32_t mutations = (rand()%255);
   bytes[0] = mutations; //TODO remove after fuzzer assetion fix
   //for(uint32_t i = 0; i < mutations; i++){
   //   len =  LLVMFuzzerMutate(bytes, len, MaxSize-8);
  // }
   size_t i;
   for(i=0;i<wire.elements_size();i++){
      totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
   }
   for(i=0;i<additions;i++){
      totalLength += encoder.appendByteArrayBlock(tlv::GenericNameComponent, bytes, len);
    }
    totalLength += encoder.prependVarNumber(totalLength);
    totalLength += encoder.prependVarNumber(tlv::Name);
    encoder.block().parse();
    const uint8_t* byteTransfer = encoder.block().wire();
    for(i = 0; i < totalLength; i++){
        Dat[i]= byteTransfer[i];
    }
    free(bytes);
    return totalLength;
}

size_t Mutator::mutateSignatureInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  //uint32_t mutationType = 1+(rand()%4);
  //TODO These all led to parsing issues, verify and check and if possible correct the issue.
  /*if(mutationType != Mutator::fieldmutation){
     switch(mutationType){
        case Mutator::deletion :
           return deleteSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::addition :
           return addSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::suffle :
           return suffleSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::TLVchange :
           return changeSigInfoTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }*/
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  wire.parse();
  Block::element_const_iterator element = wire.find(field);
  bool addExtra = false;
  if (element == wire.elements_end()){
     if( field < 255){
        wire = createField(wire, field);
        wire.parse();
        element = wire.find(field);
     }
     else {
        addExtra = true;
        bytes1[0] = 255;
     }
  }
  size_t pos = 0;
  bool multicopies = false;
  if(addExtra){
     size_t freespace = MaxSize-Size-8;
     if(MaxSize <= Size+8)
        freespace = 0;
     len =  LLVMFuzzerMutate(bytes1, 1,freespace+1);
  }
  else {
     Block::element_const_iterator element =  wire.elements_begin();
     int copies = 0;
     while(element !=  wire.elements_end()){
        if(element->type() == field)
           copies++; 
        element++;
     }
     if(copies>1){
        int randCopy = 1+rand()%copies;
        element =  wire.elements_begin(); 
        copies = 0;
        bool found = false;
        while(!found){
           if(element->type() == field)
              copies++; 
            if(copies == randCopy){
                 found = true;
                 continue;
            }
            element++;
            pos++;
        }
        multicopies = true;
     }
     else {
        element = wire.find(field);      
     }
     Block subwire = *element;
  const uint8_t* byteTransfer = subwire.value();
     for(i = 0; i < subwire.value_size(); i++){
        bytes1[i] = byteTransfer[i];
     }

     if(field == tlv::KeyLocator && copies == 1){
        if(subwire.value_size()<=1){
         len = 0;
        }
        else {
           len = mutateKeyLocator(subwire, Seed, bytes1, Size, MaxSize);
        }
     } 
     else if(field == tlv::ValidityPeriod){
        return wire.value_size();
     }
     else {
        len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
     }
  }
  size_t totalLength = 0;
  EncodingEstimator estimator;
  SignatureInfo sigInfo(tlv::DigestSha256);
  size_t estimatedSize = sigInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type() && (!multicopies || pos == i)){
        size_t temp = encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len); 
        totalLength += temp;
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  if(addExtra)
     totalLength += encoder.appendByteArrayBlock(field,  bytes1, len);
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  const uint8_t* bytes2 = encoder.block().value();
  if(totalLength>MaxSize) return wire.value_size();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}

size_t Mutator::mutateKeyLocator(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
  mutationType = Mutator::fieldmutation;
  //TODO These all led to parsing issues, verify and check and if possible correct the issue. 
  /*if(mutationType != Mutator::fieldmutation){
     switch(mutationType){
        case Mutator::deletion :
           return deleteNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::addition :
           return addNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::suffle :
           return suffleNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::TLVchange :
           return changeNameComTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }*/
  wire.parse();
  if (wire.elements_size() == 0 ) return wire.value_size();
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  int change = 0; 
  const uint8_t* byteTransfer = wire.elements()[0].value();
  for(i = 0; i < wire.elements()[0].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  if(wire.elements()[0].type() == tlv::Name){  
     len = mutateName(wire.elements()[0], Seed, bytes1, Size, MaxSize);  
     change = rand()%2;
  }
  else {
    len = mutateNonsubTLVfield(wire, wire.elements()[0].type(), Seed, bytes1, Size, MaxSize);
     len = 3;
  }
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  EncodingBuffer encoder(estimatedSize, 0);
  if(change == 1){
     for(size_t j = 0; j<3;j++)
        bytes1[j] = 1;
  }
  for(i=0;i<wire.elements_size();i++){
        if(change)
           totalLength += encoder.appendByteArrayBlock(tlv::KeyDigest,  bytes1, 3);
        else 
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::KeyLocator);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
    Dat[j] = bytes2[j];
  } 
 free(bytes1);
 return len;
}

size_t Mutator::mutateMetaInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize, int ensureSatisfaction){
  uint32_t mutationType = (rand()%5);
   if(mutationType != Mutator::fieldmutation){
     switch(mutationType){
        case Mutator::deletion :
        return deleteMeta(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::addition :
           return addMeta(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::suffle :
           return suffleMeta(wire, Seed, Dat, Size, MaxSize);
           break;
	case Mutator::TLVchange :
           return changeMetaTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }

  uint32_t field;
  do{
  field = randomlyChooseSubField(wire, Seed);
  }while(field == tlv::FreshnessPeriod &&  ensureSatisfaction > 10);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  wire.parse();
  Block::element_const_iterator element = wire.find(field);

  if (element == wire.elements_end()){
     wire = createField(wire, field);
     wire.parse();
     element = wire.find(field);
  }
  element =  wire.elements_begin();
  bool multicopies = false;
  int copies = 0;
  size_t pos = 0;
  while(element !=  wire.elements_end()){
     if(element->type() == field)
        copies++;
     element++;
  }
  if(copies>1){
     int randCopy = 1+rand()%copies;
     element =  wire.elements_begin();
     copies = 0;
     bool found = false;
     while(!found){
        if(element->type() == field)
           copies++;
         if(copies == randCopy){
              found = true;
              continue;
         }
         element++;
         pos++;
     }
     multicopies = true;
  }
  else {
     element = wire.find(field);
  }

  Block subwire = *element;
  const uint8_t* byteTransfer = element->value();
  for(i = 0; i < element->value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }
  if(field == tlv::FinalBlockId){
     len = mutateFinalBlockId(subwire, Seed, bytes1, Size, MaxSize);
  }
  else {
     len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
  }
  size_t totalLength = 0;
  EncodingEstimator estimator;
  SignatureInfo sigInfo(tlv::DigestSha256);
  size_t estimatedSize = sigInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type() && (!multicopies || pos == i)){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}

size_t Mutator::mutateFinalBlockId(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if (wire.elements_size() == 0 ) return wire.value_size();
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  wire.parse();

  const uint8_t* byteTransfer = wire.elements()[field].value();
  for(i = 0; i < wire.elements()[field].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  size_t freespace = MaxSize - Size -8;
     if(MaxSize <= Size+8)
        freespace = 0;
  len =  LLVMFuzzerMutate(bytes1, wire.elements()[field].value_size(),freespace+wire.elements()[field].value_size());

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == i)
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::FinalBlockId);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes1);
  return len;
}

size_t Mutator::mutateAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%2);
   if(mutationType == deletion){return 0;}
  wire.parse();

  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*MaxSize);
  size_t i;
  Block subwire = wire.elements()[field];
  const uint8_t* byteTransfer = subwire.value();
  for(i = 0; i < subwire.value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }
  len = mutateNonsubTLVfield(wire, subwire.type(), Seed, bytes1, Size, MaxSize);
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == i){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ApplicationParameters);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}

} // namespace nd


