#include <Windows.h>

typedef HMODULE(__stdcall* pfnLoadLib)(LPCWSTR libname);

pfnLoadLib gLoadLib = LoadLibraryW;

#if defined(_WIN64)
	const wchar_t* gLibName = L"C:\\Users\\kezzyhko\\Desktop\\DLLInjector\\x64\\Release\\library.dll";
#else
	const wchar_t* gLibName = L"C:\\Users\\kezzyhko\\Desktop\\DLLInjector\\Release\\library.dll";
#endif

DWORD _declspec(noinline) Func() {
	if (nullptr == gLoadLib(gLibName)) {
		return -1;
	}
	return 0;
}
int main() {
	Func();
}