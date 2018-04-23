sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev libgtest-dev
git submodule init && git submodule update
cd /usr/src/gtest/
sudo cmake CMakeLists.txt
sudo make
sudo cp *.a /usr/lib