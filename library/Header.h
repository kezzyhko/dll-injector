#pragma once

#ifdef MY_DLL_EXP
#define MY_API __declspec(dllexport)
#else
#define MY_API __declspec(dllimport)
#endif

extern "C" MY_API void foo();