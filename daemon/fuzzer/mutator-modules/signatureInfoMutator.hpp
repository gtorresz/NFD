#ifndef SIGINFO_MUTATOR_HPP
#define SIGINFO_MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {

size_t deleteSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeSigInfoTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
  
size_t deleteSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
	  wire.parse();
	    if(wire.elements_size() <= 1) return wire.value_size();
	      size_t totalLength = 0;
	        EncodingEstimator estimator;
		  MetaInfo metainfo;
		    size_t estimatedSize = metainfo.wireEncode(estimator);
		      uint32_t deletions = rand()%(wire.elements_size()+1);
		        uint32_t position = 1+rand()%(wire.elements_size()-1);
			  EncodingBuffer encoder(estimatedSize, 0);
			    uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
			      bytes[0] = 255;
			        size_t i;

				  for(i=0;i<wire.elements_size();i++){
					          if(i>=position && i<(position+deletions)) continue;
						          totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
							    }

				    totalLength += encoder.prependVarNumber(totalLength);
				      totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
				        size_t len = encoder.block().value_size();
					  const uint8_t* byteTransfer = encoder.block().value();
					    for(i = 0; i < len; i++){
						         Dat[i]= byteTransfer[i];
							      }

					      free(bytes);
					        return len;
}


size_t addSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
	  if((MaxSize-8) <= (Size))return wire.value_size();
	    size_t len =1, totalLength = 0;
	      EncodingEstimator estimator;
	        Name name;
		  wire.parse();
		    size_t estimatedSize = name.wireEncode(estimator);
		      EncodingBuffer encoder(estimatedSize, 0);
		        uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
			  bytes[0] = 255;
			    uint32_t sigInfoFields [7]= {tlv::SignatureType, tlv::KeyLocator, tlv::AdditionalDescription, tlv::DescriptionEntry, tlv::DescriptionKey, tlv::DescriptionValue, tlv::ValidityPeriod} ;
			      uint32_t field = rand()%6;
			        if(sigInfoFields[field] ==  tlv::KeyLocator)
					       len = 0;
				  size_t i;

				    for(i=0;i<wire.elements_size();i++){
					            totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
						      }
				            totalLength += encoder.appendByteArrayBlock(sigInfoFields[field], bytes, len);

					      totalLength += encoder.prependVarNumber(totalLength);
					        totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
						  len = encoder.block().value_size();
						    encoder.block().parse();
						      const uint8_t* byteTransfer = encoder.block().value();
						        for(i = 0; i < len; i++){
								     Dat[i]= byteTransfer[i];
								          }

							  free(bytes);
							    return len;
}

size_t suffleSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
	  wire.parse();
	    if(wire.elements_size() <= 2)return wire.value_size();
	      wire.parse();
	        size_t i, totalLength = 0;
		  EncodingEstimator estimator;
		    MetaInfo metaInfo;
		      size_t estimatedSize = metaInfo.wireEncode(estimator);
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
					          int first = 2+rand()%(wire.elements_size()-2);
						      int second = 2+rand()%(wire.elements_size()-2);
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
					  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
					    size_t len = encoder.block().value_size();
					      const uint8_t* byteTransfer = encoder.block().value();
					        for(i = 0; i < len; i++){
							     Dat[i]= byteTransfer[i];
							       }
						  free(pos);
						    return len;
}

size_t changeSigInfoTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
	  size_t totalLength = 0;
	    EncodingEstimator estimator;
	      MetaInfo metaInfo;
	        wire.parse();
		  size_t estimatedSize = metaInfo.wireEncode(estimator);

		    EncodingBuffer encoder(estimatedSize, 0);
		      uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
		        size_t component;
			  if(wire.elements_size() <= 1) return wire.value_size();
			    else component = 1+rand()%(wire.elements_size()-1);

			      for(size_t i=0;i<wire.elements_size();i++){
				              if(i == component)
						                 totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
					              else
							                 totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
						        }

			        totalLength += encoder.prependVarNumber(totalLength);
				  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
				    size_t len = encoder.block().value_size();
				      const uint8_t* byteTransfer = encoder.block().value();
				        for(size_t i = 0; i < len; i++){
						     Dat[i]= byteTransfer[i];
						       }
					  return len;
}

}
#endif
