### What?

This is a UEFI runtime driver that creates a back door (of sorts) into the Windows kernel space, accessible
by any privileged user process. It provides the following primary features:

- `EPROCESS` and `PEB` pointer lookup
- remote process memory manipulation &mdash;
read/write (including writing to write-protected pages), allocate/free, lock/unlock, query, protect
- arbitrary `HANDLE` duplication and closure
- direct page table entry substitution

The whole thing is meant to be somewhat stealthy, so as to avoid detection by various
anti-virus and anti-cheat software.

### How?

The driver is manually loaded at boot time from the UEFI shell, whereupon it hooks
the `SetVariable` runtime service by overriding its prologue with a `RET`-based detour.
When the system loads, the driver remains hidden in firmware memory,
and its functionality can be accessed by calling `NtSetSystemEnvironmentValueEx`
with specific *magic* arguments, which triggers the hook and traps
the calling (user-mode) thread in kernel space.
A second user thread then dispatches commands to the first one by using shared memory and a combination
of spinlocks and `NtAlertThreadByThreadId`/`NtWaitForAlertByThreadId` for synchronization.

---

Included in [client/](client/) is everything needed to use the driver from a userland C++ program, including a
memory manager class and a (conveniently pointer-sized) remote memory pointer class that automatically
reads, caches, and writes memory in another process.
