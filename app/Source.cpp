#include <iostream>
#include <string>
using namespace std;



bool __declspec(noinline) isPasswordCorrect(string password) {
	hash<string> hash;
	return (hash(password) == 1444710931);
	// If you are curious, it's "pa55w0rd!1"
	// But shh, I didn't tell you that
}


void __declspec(noinline) givePrize() {
	cout << "You Won!";
}


int main() {
	cout << "Enter the password: ";
	string password;
	cin >> password;

	if (!isPasswordCorrect(password)) {
		cout << "Wrong password";
		return -1;
	}

	givePrize();
	return 0;
}