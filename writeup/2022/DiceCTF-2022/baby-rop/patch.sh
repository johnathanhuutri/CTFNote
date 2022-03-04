#!/bin/sh

cp babyrop babyrop.bak
patchelf --replace-needed libc.so.6 ./libc.so.6 babyrop
patchelf --set-interpreter ./ld-linux-x86-64.so.2 babyrop
