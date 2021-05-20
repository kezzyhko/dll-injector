# dll-injector
DLL Injector for both x32 and x64 windows application

This repo contains:
* `injector` - the main code, which injects `library` into `notepad.exe` (or into `app` depending on constant).
* `library` - the dll, which currently only shows the `MessageBox`. I tried to write function hooking into it.
* `app` - the app, which I tried to inject dll into. The idea was to change the `isPasswordCorrect` function, so that it always returns `true`.