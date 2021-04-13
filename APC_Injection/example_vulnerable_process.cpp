#include <iostream>
#include <windows.h>

int main(){
    while(1){
        getchar();
        std::cout << "Waiting 2 seconds..." << std::endl;
        SleepEx(2, TRUE);
    }
}