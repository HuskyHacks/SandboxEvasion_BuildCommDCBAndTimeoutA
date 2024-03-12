# antidebug_BuildCommDCBAndTimeoutA
Antidebugging via BuildCommDCBAndTimeoutA PoC

## What is this?
While examining a known-bad malware executable in Ghidra, we found this:
![image](https://github.com/HuskyHacks/antidebug_BuildCommDCBAndTimeoutA/assets/57866415/e68dd14f-1195-4af1-bf18-55b94713a3f2)

We were originally a bit confused at the invocation of the `BuildCommDCBAndTimeoutsA` here, but originally hypothesized that it was some kind of anti-debugging feature. I think we were pretty close - it appears to be sandbox evasion. Here's why:

```
BOOL BuildCommDCBAndTimeoutsA(
  [in]  LPCSTR         lpDef,
  [out] LPDCB          lpDCB,
  [out] LPCOMMTIMEOUTS lpCommTimeouts
);

...
Return value
If the function succeeds, the return value is nonzero.
```

The specific use in the malware program is almost the opposite of what you'd expect to normally see:

```c
 if (BuildCommDCBAndTimeoutsA("jhl46745fghb", 0, 0)) {
        CurrentProcess = GetCurrentProcess();
        TerminateProcess(CurrentProcess, 0);
    }
```
... which means if this API call *succeeds*, then kill the current process. Why might that be?

There's a good chance that malware sandboxes emulate the API calls that they detect during execution, so if this program is in a malware sandbox, perhaps the emulated environment allows for bogus device strings? That's the hypothesis, anyway.
