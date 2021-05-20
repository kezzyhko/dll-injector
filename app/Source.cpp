#include <Windows.h>

#if defined(_WIN64)
    constexpr auto TITLE = L"Application x64";
#else
    constexpr auto TITLE = L"Application x32";
#endif

int main() {
    MessageBox(nullptr, L"This message is from the app", TITLE, MB_OK);
}