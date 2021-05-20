# dll-injector
DLL Injector for both x32 and x64 windows application

This project was done as an assignment on Reverse Engineering course in Innopolis University

Projects in this repo:
* `injector` - the main code, which injects `library` into `app` (or any other application depending on constant). <br>
It works for x32 or for x64 depending on how it was compiled. I.e., 32 bit version of `injector` will inject 32 bit `library` into 32 bit `app`.
* `library` - the dll, which just shows the `MessageBox` on attaching.
* `app` - the app to inject dll into.
* `shellcode` - the code that was used to get the shellcode.