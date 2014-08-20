#!/bin/bash

cd ./lib 

g++ -c config.cc packetheader.cc raw_sock.c rot_parser.cc scionbeacon.cc scioncommonlib.cc scioncryptolib.cc scionpathinfo.cc scionpathstore.cc scionprint.cc tinyxml2.cc topo_parser.cc trace.cc
ar rcs libscion.a config.o packetheader.o raw_sock.o rot_parser.o scionbeacon.o scioncommonlib.o scioncryptolib.o scionpathinfo.o scionpathstore.o scionprint.o tinyxml2.o topo_parser.o trace.o

rm -f *.o

mv libscion.a ../

echo build lib done