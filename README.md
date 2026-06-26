
# Lab 4 - Hashing, PKI, and Practical Attacks



Student: Tran Ngoc Nhat



## Scope



This project implements the hashing suite for Lab 4 and will later include:

- SHA-2 hashing

- SHA-3 hashing

- SHAKE XOF hashing

- KAT validation

- Hash benchmarking

- X.509 certificate analysis

- Controlled MD5 collision demo

- Length-extension attack demo on naive MAC construction



## Build on Windows MSYS2 UCRT64



```bash

cmake -S . -B build-windows-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Release

cmake --build build-windows-ucrt64

./build-windows-ucrt64/hashtool.exe selftest

