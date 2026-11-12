#include <iostream>
#include "helper.hpp"

int main() {
    std::cout << "Hello, Clang!" << std::endl;
    
    // Call a function from your helper file to test multi-file linking
    printMessage();
    
    return 0;
}