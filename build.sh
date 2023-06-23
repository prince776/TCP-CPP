#!/bin/sh

cmake -S . -B build
cmake --build build -j 8

cp build/compile_commands.json compile_commands.json 
