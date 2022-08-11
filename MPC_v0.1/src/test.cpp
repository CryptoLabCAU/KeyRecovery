#include <iostream>
#include <fstream>
#include <string>

using namespace std;
int main()
{

    string str= "abc" + to_string(1) + ".dat";
    cout << str <<endl;

    return 0;
}