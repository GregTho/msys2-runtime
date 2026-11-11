/* getprocaddr.c

This program is a helper for getting the pointers for the
functions in kernel32 module, and optionally injects a remote
thread that runs those functions given a pid and exit code.

We use dbghelp.dll to get the pointer to kernel32!CtrlRoutine
because it isn't exported. For that, we try to generate console
event (Ctrl+Break) ourselves, to find the pointer, and it is
printed if asked to, or a remote thread is injected to run the
given function.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Include dbghelp.h after windows.h */
#include <dbghelp.h>

static HANDLE CtrlEvent;
static void *ctrl_routine_address;

static int
inject_remote_thread_into_process (HANDLE process,
                                   LPTHREAD_START_ROUTINE address,
                                   uintptr_t exit_code,
                                   DWORD timeout_ms,
                                   DWORD *thread_return)
{
  int res = -1;
  DWORD thread_id;
  HANDLE thread;

  if (!address)
    return res;

  thread = CreateRemoteThread (process, NULL, 1024 * 1024, address,
                               (PVOID)exit_code, 0, &thread_id);
  if (!thread)
    {
      DWORD err = GetLastError ();
      DWORD proc_code = STILL_ACTIVE;
      /* If the target process exited right before or during CreateRemoteThread,
       * treat its exit as success rather than an injection failure. */
      if (WaitForSingleObject (process, 50) == WAIT_OBJECT_0
          || (GetExitCodeProcess (process, &proc_code)
              && proc_code != STILL_ACTIVE))
        {
          if (thread_return != NULL)
            *thread_return = 0;
          return 0;
        }
      SetLastError (err);
      return -1;
    }

  /*
   * Wait for either the target process to exit or the injected thread to
   * finish. SetConsoleCtrlHandler() callbacks commonly block/sleep on the
   * CtrlRoutine thread while the main thread cleans up and exits the process
   * (because returning from a handler causes Windows to terminate the process
   * immediately).
   */
  HANDLE handles[2] = { process, thread };
  DWORD wait_res = WaitForMultipleObjects (2, handles, FALSE, timeout_ms);
  if (wait_res == WAIT_OBJECT_0)
    {
      res = 0;
      if (thread_return != NULL)
        *thread_return = 0;
    }
  else if (wait_res == WAIT_OBJECT_0 + 1)
    {
      DWORD code = 0;
      res = 0;
      if (!GetExitCodeThread (thread, &code))
        code = 1;
      /*
       * According to the docs at MSDN for GetExitCodeThread, it will
       * get the return value from the function, here CtrlRoutine.
       * CtrlRoutine returns 0 when a CtrlEvent handler handled the event.
       * However, when DefaultHandler or another thread calls ExitProcess()
       * (e.g. with STATUS_CONTROL_C_EXIT), the kernel terminates our remote
       * thread with that exit code microseconds before the process object
       * itself signals. If the process exited, treat it as handled.
       */
      if (code != 0)
        {
          DWORD proc_code = STILL_ACTIVE;
          if (WaitForSingleObject (process, 100) == WAIT_OBJECT_0
              || (GetExitCodeProcess (process, &proc_code)
                  && proc_code != STILL_ACTIVE))
            code = 0;
        }
      if (thread_return != NULL)
        *thread_return = code;
    }

  CloseHandle (thread);
  return res;
}

/* Here, we send a CtrlEvent to the current process for the
 * sole purpose of capturing the address of the CtrlRoutine
 * function, by looking the stack trace.
 *
 * This hack is needed because we cannot use GetProcAddress()
 * as we do for exported functions, because CtrlRoutine is not
 * exported (although the .pdb files ensure that we can see
 * it in a debugger).
 */
static WINAPI BOOL
ctrl_handler (DWORD ctrl_type)
{
  unsigned short count;
  void *address;
  HANDLE process;
  PSYMBOL_INFOW info = NULL;
  DWORD64 displacement;

  (void)ctrl_type;

  count = CaptureStackBackTrace (1l /* skip this function */,
                                 1l /* return only one trace item */, &address,
                                 NULL);
  if (count != 1)
    {
      fprintf (stderr, "Could not capture backtrace\n");
      goto out;
    }

  process = GetCurrentProcess ();
  if (!SymInitialize (process, NULL, TRUE))
    {
      fprintf (stderr, "Could not initialize symbols\n");
      goto out;
    }

  info = (PSYMBOL_INFOW)malloc (sizeof (*info)
                                + MAX_SYM_NAME * sizeof (wchar_t));
  if (!info)
    {
      fprintf (stderr, "Could not allocate symbol info structure\n");
      SymCleanup (process);
      goto out;
    }
  info->SizeOfStruct = sizeof (*info);
  info->MaxNameLen = MAX_SYM_NAME;

  if (!SymFromAddrW (process, (DWORD64) (uintptr_t)address, &displacement,
                     info))
    {
      fprintf (stderr, "Could not get symbol info\n");
      free (info);
      SymCleanup (process);
      goto out;
    }

  ctrl_routine_address = (void *)(uintptr_t)info->Address;
  free (info);
  SymCleanup (process);

out:
  if (CtrlEvent && !SetEvent (CtrlEvent))
    fprintf (stderr, "SetEvent failed (%lu)\n", GetLastError ());
  return TRUE;
}

/* The easy route for finding the address of CtrlRoutine
 * would be use GetProcAddress() but this isn't viable
 * here because that symbol isn't exported.
 */
static void *
find_ctrl_routine_the_hard_way (void)
{
  /*
   * Avoid terminating all processes attached to the current console;
   * This would happen if we used the same console as the caller, though,
   * because we are sending a CtrlEvent on purpose (which _is_ sent to
   * all processes connected to the same console, and the other processes
   * are most likely unprepared for that CTRL_BREAK_EVENT and would be
   * terminated as a consequence, _including the caller_).
   *
   * In case we get only one result from GetConsoleProcessList(), we don't
   * need to create and allocate a new console, and it could avoid a console
   * window popping up.
   */
  DWORD proc_list[2];
  DWORD count;
  ctrl_routine_address = NULL;
  count = GetConsoleProcessList (proc_list, 2);
  if (count != 1)
    {
      if (count > 1
          && !FreeConsole () && GetLastError () != ERROR_INVALID_PARAMETER)
        {
          fprintf (stderr, "Could not detach from current Console: %lu\n",
                   GetLastError ());
          return NULL;
        }
      if (!AllocConsole ())
        {
          fprintf (stderr, "Could not allocate a new Console: %lu\n",
                   GetLastError ());
          return NULL;
        }
    }

  CtrlEvent = CreateEvent (NULL,  // default security attributes
                           TRUE,  // manual-reset event
                           FALSE, // initial state is nonsignaled
                           NULL   // object name
  );

  if (CtrlEvent == NULL)
    {
      fprintf (stderr, "CreateEvent failed (%lu)\n", GetLastError ());
      return NULL;
    }

  if (!SetConsoleCtrlHandler (ctrl_handler, TRUE))
    {
      fprintf (stderr, "Could not register Ctrl handler\n");
      CloseHandle (CtrlEvent);
      CtrlEvent = NULL;
      return NULL;
    }

  if (!GenerateConsoleCtrlEvent (CTRL_BREAK_EVENT, 0))
    {
      fprintf (stderr, "Could not simulate Ctrl+Break\n");
      SetConsoleCtrlHandler (ctrl_handler, FALSE);
      CloseHandle (CtrlEvent);
      CtrlEvent = NULL;
      return NULL;
    }

  if (WaitForSingleObject (CtrlEvent, 10000 /* 10 seconds*/) != WAIT_OBJECT_0)
    fprintf (stderr, "WaitForSingleObject failed (%lu)\n", GetLastError ());

  SetConsoleCtrlHandler (ctrl_handler, FALSE);
  CloseHandle (CtrlEvent);
  CtrlEvent = NULL;
  return ctrl_routine_address;
}

static void *
get_proc_addr (const char * module_name, const char * function_name)
{
  HMODULE module = GetModuleHandle (module_name);
  if (!module)
    return NULL;
  return (void *)GetProcAddress (module, function_name);
}

int
main (int argc, char **argv)
{
  DWORD pid = 0;
  uintptr_t exit_code = 0;
  DWORD timeout_ms = 10000;
  void *address;
  BOOL is_ctrl_routine;
  DWORD thread_return = 0;

  if (argc == 4 || argc == 5)
    {
      char *endp = NULL;
      exit_code = (uintptr_t)strtoull (argv[2], &endp, 0);
      if (endp == argv[2] || *endp != '\0')
        {
          fprintf (stderr, "Invalid exit code: %s\n", argv[2]);
          return 1;
        }
      pid = strtoul (argv[3], &endp, 0);
      if (pid == 0 || endp == argv[3] || *endp != '\0')
        {
          fprintf (stderr, "Invalid pid: %s\n", argv[3]);
          return 1;
        }
      if (argc == 5)
        {
          timeout_ms = strtoul (argv[4], &endp, 0);
          if (endp == argv[4] || *endp != '\0')
            {
              fprintf (stderr, "Invalid timeout_ms: %s\n", argv[4]);
              return 1;
            }
        }
    }
  else if (argc == 2)
    {
      pid = 0;
    }
  else
    {
      fprintf (stderr, "Need a function name, exit code and pid [timeout_ms]\n"
               "Or needs a function name.\n");
      return 1;
    }

  is_ctrl_routine = strcmp (argv[1], "CtrlRoutine") == 0;
  address = get_proc_addr ("kernel32", argv[1]);
  if (is_ctrl_routine && !address)
    {
      /* CtrlRoutine is undocumented, and has been seen in both
       * kernel32 and kernelbase
       */
      address = get_proc_addr ("kernelbase", argv[1]);
      if (!address)
        address = find_ctrl_routine_the_hard_way ();
    }

  if (!address)
    {
      fprintf (stderr, "Could not get proc address\n");
      return 1;
    }

  if (argc == 2)
    {
      printf ("%p\n", address);
      fflush (stdout);
      return 0;
    }

  HANDLE h = OpenProcess (PROCESS_CREATE_THREAD |
                          PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                          PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
                          FALSE, pid);
  if (h == NULL)
    {
      DWORD err = GetLastError ();
      if (err == ERROR_INVALID_PARAMETER)
        return 0;
      fprintf (stderr, "OpenProcess failed: %lu\n", err);
      return 1;
    }

  /* Inject the remote thread */
  if (inject_remote_thread_into_process (h, (LPTHREAD_START_ROUTINE)address,
                                         exit_code, timeout_ms,
                                         &thread_return) < 0)
    {
      fprintf (stderr, "Could not inject thread into process %lu\n", pid);
      CloseHandle (h);
      return 1;
    }

  CloseHandle (h);

  if (is_ctrl_routine && thread_return)
    {
      fprintf (stderr,
               "Injected remote thread for pid %lu returned %lu\n", pid,
               thread_return);
      return 1;
    }

  return 0;
}
