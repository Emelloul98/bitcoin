# CMake generated Testfile for 
# Source directory: /home/student/CLionProjects/projects/bitcoin
# Build directory: /home/student/CLionProjects/projects/bitcoin/cmake-build-debug
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[util_test_runner]=] "/snap/clion/296/bin/cmake/linux/x64/bin/cmake" "-E" "env" "BITCOINUTIL=/home/student/CLionProjects/projects/bitcoin/cmake-build-debug/src/bitcoin-util" "BITCOINTX=/home/student/CLionProjects/projects/bitcoin/cmake-build-debug/src/bitcoin-tx" "/usr/bin/python3.10" "/home/student/CLionProjects/projects/bitcoin/cmake-build-debug/test/util/test_runner.py")
set_tests_properties([=[util_test_runner]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/student/CLionProjects/projects/bitcoin/cmake/tests.cmake;6;add_test;/home/student/CLionProjects/projects/bitcoin/cmake/tests.cmake;0;;/home/student/CLionProjects/projects/bitcoin/CMakeLists.txt;574;include;/home/student/CLionProjects/projects/bitcoin/CMakeLists.txt;0;")
add_test([=[util_rpcauth_test]=] "/usr/bin/python3.10" "/home/student/CLionProjects/projects/bitcoin/cmake-build-debug/test/util/rpcauth-test.py")
set_tests_properties([=[util_rpcauth_test]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/student/CLionProjects/projects/bitcoin/cmake/tests.cmake;12;add_test;/home/student/CLionProjects/projects/bitcoin/cmake/tests.cmake;0;;/home/student/CLionProjects/projects/bitcoin/CMakeLists.txt;574;include;/home/student/CLionProjects/projects/bitcoin/CMakeLists.txt;0;")
subdirs("test")
subdirs("doc")
subdirs("src")
