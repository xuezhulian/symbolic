#!/bin/bash

cargo build --release;
cp /Users/yuencong/workplace/symbolic/target/release/libsymbolic_cabi.dylib /Users/yuencong/Library/Python/3.9/lib/python/site-packages/kssymbolic/_lowlevel__lib.so
