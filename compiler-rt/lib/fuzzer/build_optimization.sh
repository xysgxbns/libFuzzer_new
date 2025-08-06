#!/bin/sh
LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang++}"
for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX -stdlib=libc++ -fPIC -O2 -std=c++11 $f -c &
done
wait
rm -f libFuzzer.a
ar r libFuzzer.a *.o
rm -f Fuzzer*.o