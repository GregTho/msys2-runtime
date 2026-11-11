/* win32-proctree.c: Native Win32 helper for testing exit_process_tree().

   This file is part of Cygwin / MSYS2.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for details. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE g_stdout_handle = INVALID_HANDLE_VALUE;
static HANDLE g_stdin_handle = INVALID_HANDLE_VALUE;
static HANDLE g_ctrl_event = NULL;
static HANDLE g_worker_locked_event = NULL;
static HANDLE g_stop_worker_event = NULL;
static CRITICAL_SECTION g_cs;
static volatile LONG g_worker_clean = 0;
static volatile LONG g_sigint_count = 0;
static const char *g_marker_path = NULL;
static BOOL g_record_break = FALSE;

static void
write_all (HANDLE h, const char *buf, DWORD len)
{
  DWORD off = 0;
  if (h == NULL || h == INVALID_HANDLE_VALUE)
    return;
  while (off < len)
    {
      DWORD written = 0;
      if (!WriteFile (h, buf + off, len - off, &written, NULL) || written == 0)
        break;
      off += written;
    }
}

static void
write_str (HANDLE h, const char *s)
{
  write_all (h, s, (DWORD) strlen (s));
}

static void
append_marker (const char *path, const char *text)
{
  HANDLE hf;
  if (!path || !path[0])
    return;
  hf = CreateFileA (path, FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hf == INVALID_HANDLE_VALUE)
    return;
  write_str (hf, text);
  FlushFileBuffers (hf);
  CloseHandle (hf);
}

static BOOL
read_line (HANDLE h, char *buf, size_t cap)
{
  size_t pos = 0;
  if (cap == 0)
    return FALSE;
  while (pos + 1 < cap)
    {
      char ch = 0;
      DWORD got = 0;
      if (!ReadFile (h, &ch, 1, &got, NULL) || got == 0)
        break;
      if (ch == '\r')
        continue;
      if (ch == '\n')
        {
          buf[pos] = '\0';
          return TRUE;
        }
      buf[pos++] = ch;
    }
  buf[pos] = '\0';
  return pos > 0;
}

static DWORD WINAPI
watchdog_thread (LPVOID param)
{
  (void) param;
  Sleep (20000);
  ExitProcess (124);
  return 0;
}

/* Simulates a real-world SetConsoleCtrlHandler callback that signals the
   main thread to perform graceful teardown and blocks on the CtrlRoutine
   thread so Windows DefaultHandler does not terminate the process early. */
static BOOL WINAPI
coord_ctrl_handler (DWORD ctrl_type)
{
  if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT)
    {
      if (g_ctrl_event)
        SetEvent (g_ctrl_event);
      Sleep (6000);
      return TRUE;
    }
  return FALSE;
}

static BOOL WINAPI
unexpected_ctrl_handler (DWORD ctrl_type)
{
  if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT)
    {
      append_marker (g_marker_path, "UNEXPECTED_CHILD_CTRL\n");
      ExitProcess (99);
    }
  return FALSE;
}

static BOOL WINAPI
repl_ctrl_handler (DWORD ctrl_type)
{
  if (ctrl_type == CTRL_C_EVENT)
    {
      LONG c = InterlockedIncrement (&g_sigint_count);
      char msg[64];
      snprintf (msg, sizeof (msg), "SIGINT %ld\n", (long) c);
      write_str (g_stdout_handle, msg);
      return TRUE;
    }
  if (ctrl_type == CTRL_BREAK_EVENT)
    {
      LONG c = InterlockedCompareExchange (&g_sigint_count, 0, 0);
      char msg[64];
      snprintf (msg, sizeof (msg), "SIGINT_COUNT=%ld\n", (long) c);
      append_marker (g_marker_path, msg);
      if (g_ctrl_event)
        SetEvent (g_ctrl_event);
      Sleep (6000);
      return TRUE;
    }
  return FALSE;
}

static BOOL WINAPI
stubborn_ctrl_handler (DWORD ctrl_type)
{
  if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT)
    {
      if (ctrl_type == CTRL_BREAK_EVENT && g_record_break)
        append_marker (g_marker_path, "GOT_BREAK\n");
      return TRUE;
    }
  return FALSE;
}

static DWORD WINAPI
lock_holder_thread (LPVOID param)
{
  (void) param;
  EnterCriticalSection (&g_cs);
  SetEvent (g_worker_locked_event);
  WaitForSingleObject (g_stop_worker_event, 15000);
  InterlockedExchange (&g_worker_clean, 1);
  LeaveCriticalSection (&g_cs);
  return 0;
}

static BOOL
spawn_self (const char *submode, const char *marker_path,
            HANDLE *out_cmd_wr, HANDLE *out_info_rd,
            PROCESS_INFORMATION *out_pi)
{
  char exe[MAX_PATH];
  char cmdline[MAX_PATH * 2 + 64];
  SECURITY_ATTRIBUTES sa;
  HANDLE cmd_rd = NULL, cmd_wr = NULL;
  HANDLE info_rd = NULL, info_wr = NULL;
  STARTUPINFOA si;
  DWORD len;

  len = GetModuleFileNameA (NULL, exe, sizeof (exe));
  if (len == 0 || len >= sizeof (exe))
    return FALSE;

  memset (&sa, 0, sizeof (sa));
  sa.nLength = sizeof (sa);
  sa.bInheritHandle = TRUE;

  if (!CreatePipe (&cmd_rd, &cmd_wr, &sa, 0))
    return FALSE;
  SetHandleInformation (cmd_wr, HANDLE_FLAG_INHERIT, 0);

  if (!CreatePipe (&info_rd, &info_wr, &sa, 0))
    {
      CloseHandle (cmd_rd);
      CloseHandle (cmd_wr);
      return FALSE;
    }
  SetHandleInformation (info_rd, HANDLE_FLAG_INHERIT, 0);

  int cmd_len = snprintf (cmdline, sizeof (cmdline), "\"%s\" %s \"%s\"",
                          exe, submode, marker_path ? marker_path : "");
  if (cmd_len < 0 || (size_t) cmd_len >= sizeof (cmdline))
    {
      CloseHandle (cmd_rd);
      CloseHandle (cmd_wr);
      CloseHandle (info_rd);
      CloseHandle (info_wr);
      return FALSE;
    }

  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = cmd_rd;
  si.hStdOutput = info_wr;
  si.hStdError = INVALID_HANDLE_VALUE;

  memset (out_pi, 0, sizeof (*out_pi));
  if (!CreateProcessA (exe, cmdline, NULL, NULL, TRUE, 0, NULL, NULL,
                       &si, out_pi))
    {
      CloseHandle (cmd_rd);
      CloseHandle (cmd_wr);
      CloseHandle (info_rd);
      CloseHandle (info_wr);
      return FALSE;
    }

  CloseHandle (cmd_rd);
  CloseHandle (info_wr);
  *out_cmd_wr = cmd_wr;
  *out_info_rd = info_rd;
  return TRUE;
}

static int
run_mt_graceful_term (void)
{
  HANDLE worker;
  char msg[64];

  InitializeCriticalSection (&g_cs);
  g_ctrl_event = CreateEventA (NULL, TRUE, FALSE, NULL);
  g_worker_locked_event = CreateEventA (NULL, TRUE, FALSE, NULL);
  g_stop_worker_event = CreateEventA (NULL, TRUE, FALSE, NULL);
  if (!g_ctrl_event || !g_worker_locked_event || !g_stop_worker_event)
    return 2;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (coord_ctrl_handler, TRUE))
    return 2;

  worker = CreateThread (NULL, 0, lock_holder_thread, NULL, 0, NULL);
  if (!worker)
    return 2;

  if (WaitForSingleObject (g_worker_locked_event, 5000) != WAIT_OBJECT_0)
    return 2;

  snprintf (msg, sizeof (msg), "READY %lu\n",
            (unsigned long) GetCurrentProcessId ());
  write_str (g_stdout_handle, msg);

  if (WaitForSingleObject (g_ctrl_event, 15000) != WAIT_OBJECT_0)
    return 3;

  SetEvent (g_stop_worker_event);
  if (WaitForSingleObject (worker, 5000) != WAIT_OBJECT_0)
    return 4;
  CloseHandle (worker);

  /* Acquire the critical section held by the worker thread to prove no thread
     was killed mid-lock by an injected ExitProcess() or premature TerminateProcess(). */
  EnterCriticalSection (&g_cs);
  if (InterlockedCompareExchange (&g_worker_clean, 0, 0) == 1)
    append_marker (g_marker_path, "MT_CLEAN_OK\n");
  LeaveCriticalSection (&g_cs);

  ExitProcess (0);
  return 0;
}

static int
run_tree_leaf (void)
{
  char msg[64];
  char ch = 0;
  DWORD got = 0;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (unexpected_ctrl_handler, TRUE))
    return 2;

  snprintf (msg, sizeof (msg), "LEAF_READY %lu\n",
            (unsigned long) GetCurrentProcessId ());
  write_str (g_stdout_handle, msg);

  if (!ReadFile (g_stdin_handle, &ch, 1, &got, NULL) || got != 1 || ch != 'Q')
    return 98;

  ExitProcess (0);
  return 0;
}

static int
run_tree_worker (void)
{
  HANDLE leaf_cmd_wr = NULL, leaf_info_rd = NULL;
  PROCESS_INFORMATION pi_leaf;
  char line[128];
  unsigned long leaf_pid = 0;
  char msg[128];
  char ch = 0;
  DWORD got = 0;
  DWORD leaf_ec = 1;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (unexpected_ctrl_handler, TRUE))
    return 2;

  if (!spawn_self ("tree-leaf", g_marker_path, &leaf_cmd_wr, &leaf_info_rd,
                   &pi_leaf))
    return 2;

  if (!read_line (leaf_info_rd, line, sizeof (line))
      || sscanf (line, "LEAF_READY %lu", &leaf_pid) != 1)
    {
      TerminateProcess (pi_leaf.hProcess, 1);
      return 2;
    }
  CloseHandle (leaf_info_rd);

  snprintf (msg, sizeof (msg), "WORKER_READY %lu %lu\n",
            (unsigned long) GetCurrentProcessId (), leaf_pid);
  write_str (g_stdout_handle, msg);

  if (!ReadFile (g_stdin_handle, &ch, 1, &got, NULL) || got != 1 || ch != 'Q')
    {
      TerminateProcess (pi_leaf.hProcess, 1);
      return 98;
    }

  write_all (leaf_cmd_wr, "Q", 1);
  CloseHandle (leaf_cmd_wr);

  if (WaitForSingleObject (pi_leaf.hProcess, 5000) != WAIT_OBJECT_0
      || !GetExitCodeProcess (pi_leaf.hProcess, &leaf_ec)
      || leaf_ec != 0)
    {
      TerminateProcess (pi_leaf.hProcess, 1);
      return 97;
    }

  CloseHandle (pi_leaf.hThread);
  CloseHandle (pi_leaf.hProcess);
  ExitProcess (0);
  return 0;
}

static int
run_tree_coord (void)
{
  HANDLE worker_cmd_wr = NULL, worker_info_rd = NULL;
  PROCESS_INFORMATION pi_worker;
  char line[128];
  unsigned long worker_pid = 0, leaf_pid = 0;
  char msg[128];
  HANDLE waits[2];
  DWORD wres;
  DWORD worker_ec = 1;

  g_ctrl_event = CreateEventA (NULL, TRUE, FALSE, NULL);
  if (!g_ctrl_event)
    return 2;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (coord_ctrl_handler, TRUE))
    return 2;

  if (!spawn_self ("tree-worker", g_marker_path, &worker_cmd_wr,
                   &worker_info_rd, &pi_worker))
    return 2;

  if (!read_line (worker_info_rd, line, sizeof (line))
      || sscanf (line, "WORKER_READY %lu %lu", &worker_pid, &leaf_pid) != 2)
    {
      TerminateProcess (pi_worker.hProcess, 1);
      return 2;
    }
  CloseHandle (worker_info_rd);

  snprintf (msg, sizeof (msg), "READY %lu %lu %lu\n",
            (unsigned long) GetCurrentProcessId (), worker_pid, leaf_pid);
  write_str (g_stdout_handle, msg);

  waits[0] = g_ctrl_event;
  waits[1] = pi_worker.hProcess;
  wres = WaitForMultipleObjects (2, waits, FALSE, 15000);
  if (wres != WAIT_OBJECT_0)
    {
      append_marker (g_marker_path, "FAIL_BOTTOM_UP\n");
      TerminateProcess (pi_worker.hProcess, 1);
      ExitProcess (2);
    }

  write_all (worker_cmd_wr, "Q", 1);
  CloseHandle (worker_cmd_wr);

  if (WaitForSingleObject (pi_worker.hProcess, 5000) != WAIT_OBJECT_0
      || !GetExitCodeProcess (pi_worker.hProcess, &worker_ec)
      || worker_ec != 0)
    {
      append_marker (g_marker_path, "FAIL_WORKER_EXIT\n");
      TerminateProcess (pi_worker.hProcess, 1);
      ExitProcess (3);
    }

  CloseHandle (pi_worker.hThread);
  CloseHandle (pi_worker.hProcess);
  append_marker (g_marker_path, "TREE_ORDER_OK\n");
  ExitProcess (0);
  return 0;
}

static int
run_repl (void)
{
  char msg[64];

  g_ctrl_event = CreateEventA (NULL, TRUE, FALSE, NULL);
  if (!g_ctrl_event)
    return 2;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (repl_ctrl_handler, TRUE))
    return 2;

  snprintf (msg, sizeof (msg), "READY %lu\n",
            (unsigned long) GetCurrentProcessId ());
  write_str (g_stdout_handle, msg);

  if (WaitForSingleObject (g_ctrl_event, 15000) != WAIT_OBJECT_0)
    return 3;

  ExitProcess (0);
  return 0;
}

static int
run_repl_normal_exit (void)
{
  char msg[64];
  DWORD waited = 0;

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (repl_ctrl_handler, TRUE))
    return 2;

  snprintf (msg, sizeof (msg), "READY %lu\n",
            (unsigned long) GetCurrentProcessId ());
  write_str (g_stdout_handle, msg);

  while (InterlockedCompareExchange (&g_sigint_count, 0, 0) < 1)
    {
      if (waited >= 15000)
        return 3;
      Sleep (10);
      waited += 10;
    }

  /* Exit after the 200ms coordinator_grace_ms window in exit_process_tree()
     to verify that exceptions.cc clears sigExeced when ch_spawn survives
     SIGINT and later exits normally with 0. */
  Sleep (300);
  append_marker (g_marker_path, "REPL_NORMAL_EXIT\n");
  ExitProcess (0);
  return 0;
}

static int
run_mixed_tree (const char *msys_exe, const char *bridge_mode)
{
  char self_exe[MAX_PATH];
  char cmdline[MAX_PATH * 3 + 128];
  SECURITY_ATTRIBUTES sa;
  HANDLE info_rd = NULL, info_wr = NULL;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi_msys;
  char line[128], msg[128];
  unsigned long leaf_pid = 0;
  DWORD len;

  if (!msys_exe || !msys_exe[0] || !bridge_mode || !bridge_mode[0])
    return 2;

  len = GetModuleFileNameA (NULL, self_exe, sizeof (self_exe));
  if (len == 0 || len >= sizeof (self_exe))
    return 2;

  g_record_break = TRUE;
  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (stubborn_ctrl_handler, TRUE))
    return 2;

  memset (&sa, 0, sizeof (sa));
  sa.nLength = sizeof (sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe (&info_rd, &info_wr, &sa, 0))
    return 2;
  SetHandleInformation (info_rd, HANDLE_FLAG_INHERIT, 0);

  snprintf (cmdline, sizeof (cmdline), "\"%s\" %s \"%s\" \"%s\"",
            msys_exe, bridge_mode, self_exe, g_marker_path ? g_marker_path : "");

  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = INVALID_HANDLE_VALUE;
  si.hStdOutput = info_wr;
  si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
  memset (&pi_msys, 0, sizeof (pi_msys));

  if (!CreateProcessA (msys_exe, cmdline, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi_msys))
    {
      CloseHandle (info_rd);
      CloseHandle (info_wr);
      return 2;
    }
  CloseHandle (info_wr);

  if (!read_line (info_rd, line, sizeof (line))
      || sscanf (line, "LEAF_READY %lu", &leaf_pid) != 1)
    {
      TerminateProcess (pi_msys.hProcess, 1);
      CloseHandle (info_rd);
      CloseHandle (pi_msys.hThread);
      CloseHandle (pi_msys.hProcess);
      return 2;
    }
  CloseHandle (info_rd);

  snprintf (msg, sizeof (msg), "READY %lu %lu %lu\n",
            (unsigned long) GetCurrentProcessId (),
            (unsigned long) pi_msys.dwProcessId, leaf_pid);
  write_str (g_stdout_handle, msg);

  Sleep (15000);
  CloseHandle (pi_msys.hThread);
  CloseHandle (pi_msys.hProcess);
  return 0;
}

static int
run_stubborn_leaf (void)
{
  char msg[64];

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (stubborn_ctrl_handler, TRUE))
    return 2;

  snprintf (msg, sizeof (msg), "LEAF_READY %lu\n",
            (unsigned long) GetCurrentProcessId ());
  write_str (g_stdout_handle, msg);

  Sleep (15000);
  return 0;
}

static int
run_stubborn_worker (void)
{
  HANDLE leaf_cmd_wr = NULL, leaf_info_rd = NULL;
  PROCESS_INFORMATION pi_leaf;
  char line[128];
  unsigned long leaf_pid = 0;
  char msg[128];

  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (stubborn_ctrl_handler, TRUE))
    return 2;

  if (!spawn_self ("stubborn-leaf", g_marker_path, &leaf_cmd_wr, &leaf_info_rd,
                   &pi_leaf))
    return 2;

  if (!read_line (leaf_info_rd, line, sizeof (line))
      || sscanf (line, "LEAF_READY %lu", &leaf_pid) != 1)
    {
      TerminateProcess (pi_leaf.hProcess, 1);
      return 2;
    }
  CloseHandle (leaf_info_rd);

  snprintf (msg, sizeof (msg), "WORKER_READY %lu %lu\n",
            (unsigned long) GetCurrentProcessId (), leaf_pid);
  write_str (g_stdout_handle, msg);

  Sleep (15000);
  CloseHandle (leaf_cmd_wr);
  CloseHandle (pi_leaf.hThread);
  CloseHandle (pi_leaf.hProcess);
  return 0;
}

static int
run_stubborn_tree (void)
{
  HANDLE worker_cmd_wr = NULL, worker_info_rd = NULL;
  PROCESS_INFORMATION pi_worker;
  char line[128];
  unsigned long worker_pid = 0, leaf_pid = 0;
  char msg[128];

  g_record_break = TRUE;
  SetConsoleCtrlHandler (NULL, FALSE);
  if (!SetConsoleCtrlHandler (stubborn_ctrl_handler, TRUE))
    return 2;

  if (!spawn_self ("stubborn-worker", g_marker_path, &worker_cmd_wr,
                   &worker_info_rd, &pi_worker))
    return 2;

  if (!read_line (worker_info_rd, line, sizeof (line))
      || sscanf (line, "WORKER_READY %lu %lu", &worker_pid, &leaf_pid) != 2)
    {
      TerminateProcess (pi_worker.hProcess, 1);
      return 2;
    }
  CloseHandle (worker_info_rd);

  snprintf (msg, sizeof (msg), "READY %lu %lu %lu\n",
            (unsigned long) GetCurrentProcessId (), worker_pid, leaf_pid);
  write_str (g_stdout_handle, msg);

  Sleep (15000);
  CloseHandle (worker_cmd_wr);
  CloseHandle (pi_worker.hThread);
  CloseHandle (pi_worker.hProcess);
  return 0;
}

int
main (int argc, char **argv)
{
  HANDLE wd;
  const char *mode;

  if (argc < 2)
    return 1;

  mode = argv[1];
  g_marker_path = (argc >= 3) ? argv[2] : "";

  g_stdin_handle = GetStdHandle (STD_INPUT_HANDLE);
  g_stdout_handle = GetStdHandle (STD_OUTPUT_HANDLE);
  if (g_stdin_handle && g_stdin_handle != INVALID_HANDLE_VALUE)
    SetHandleInformation (g_stdin_handle, HANDLE_FLAG_INHERIT, 0);
  if (g_stdout_handle && g_stdout_handle != INVALID_HANDLE_VALUE)
    SetHandleInformation (g_stdout_handle, HANDLE_FLAG_INHERIT, 0);

  wd = CreateThread (NULL, 0, watchdog_thread, NULL, 0, NULL);
  if (wd)
    CloseHandle (wd);

  if (strcmp (mode, "mt-graceful-term") == 0)
    return run_mt_graceful_term ();
  if (strcmp (mode, "tree-coord") == 0)
    return run_tree_coord ();
  if (strcmp (mode, "tree-worker") == 0)
    return run_tree_worker ();
  if (strcmp (mode, "tree-leaf") == 0)
    return run_tree_leaf ();
  if (strcmp (mode, "repl") == 0)
    return run_repl ();
  if (strcmp (mode, "repl-normal-exit") == 0)
    return run_repl_normal_exit ();
  if (strcmp (mode, "stubborn-tree") == 0)
    return run_stubborn_tree ();
  if (strcmp (mode, "stubborn-worker") == 0)
    return run_stubborn_worker ();
  if (strcmp (mode, "stubborn-leaf") == 0)
    return run_stubborn_leaf ();
  if (strcmp (mode, "mixed-tree") == 0)
    return run_mixed_tree (argc >= 4 ? argv[3] : "", argc >= 5 ? argv[4] : "");

  return 1;
}
