#!/bin/bash
for filename in ../FuzzerTrace/*
do
    sudo LLVM_PROFILE_FILE="rawData/$filename.profraw"./../build/daemon/visualizer "$filename" 
done
llvm-profdata merge -sparse ../*.profraw -o ../data.profdata
llvm-cov report ./../build/daemon/visualizer -instr-profile=data.profdata
