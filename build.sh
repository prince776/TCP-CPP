#!/bin/sh

cmake -S . -B build
cmake --build build

cp build/compile_commands.json compile_commands.json 
