sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev libgtest-dev


sudo apt-cache show libjsonrpccpp-dev

if [$? -ne 0];
then
    sudo apt-get install libjsonrpccpp-dev libjsonrpccpp-tools
else
    sudo apt-get install libjson-rpc-cpp-dev libjson-rpc-cpp-tools
fi


git submodule init && git submodule update
cd /usr/src/gtest/
sudo cmake CMakeLists.txt
sudo make
sudo cp *.a /usr/lib
