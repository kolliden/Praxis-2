cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/webserver 127.0.0.1 1234