#!/bin/bash

curl -sSf https://static.rust-lang.org/rustup.sh | sh
python3 -m pip install --upgrade build
export PWD=`pwd`
export SHOULD_COMPILE=true
rm -rf py/dist/*.whl
python3 -m build ./py
pip3 install py/dist/*.whl --force-reinstall
