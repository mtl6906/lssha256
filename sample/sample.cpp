#include "ls/SHA256.h"
#include "iostream"

using namespace ls;
using namespace std;

int main()
{
	SHA256 sha256;
	string str1 = "123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789";
	string str2 = "123";
	cout << sha256.hash(str1) << endl;
	cout << sha256.hash(str2) << endl;
	cout << sha256.hmac("123", "456") << endl;
	return 0;
}
