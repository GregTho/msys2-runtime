#ifndef EXIT_PROCESS_H
#define EXIT_PROCESS_H

/*
 * This file contains functions to signal or terminate a Win32 process tree
 * cleanly and safely.
 *
 * As we do not want to export these helpers in the MSYS2 runtime ABI, these
 * functions are marked as file-local (static).
 *
 * Strategy by signal:
 * - SIGINT / SIGQUIT: Inject kernel32/kernelbase!CtrlRoutine(CTRL_C_EVENT or
 *   CTRL_BREAK_EVENT) top-down via getprocaddr*.exe so SetConsoleCtrlHandler()
 *   callbacks run and parent coordinators can orchestrate child shutdown.
 *   Never fall through to ExitProcess() or TerminateProcess(): processes that
 *   catch or ignore Ctrl+C (such as interactive REPLs) must stay alive.
 * - SIGTERM: Inject CtrlRoutine(CTRL_BREAK_EVENT) top-down first and allow up
 *   to a 500ms total tree grace period for graceful shutdown, then sweep any
 *   surviving Win32 processes top-down with TerminateProcess(). Never inject
 *   ExitProcess(), which runs LdrShutdownProcess()/DllMain concurrently with
 *   active worker threads and causes loader-lock deadlocks or heap corruption.
 * - SIGKILL / other fatal signals: Sweep top-down with TerminateProcess().
 *
 * All descendant lookups validate GetProcessTimes() creation timestamps
 * (child_create_time >= parent_create_time) and pin opened process HANDLEs
 * across the entire operation to prevent PID-reuse collateral damage.
 */

#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/cygwin.h>
#include <tlhelp32.h>
#include <unistd.h>
#include <wchar.h>

static BOOL get_wow (HANDLE process, BOOL &is_wow, USHORT &process_arch);
static int exit_process_tree (HANDLE main_process, int exit_code);

static BOOL
kill_via_console_helper (HANDLE process, const wchar_t *function_name,
                         int exit_code, DWORD pid, DWORD timeout_ms)
{
  BOOL is_wow;
  USHORT process_arch;
  if (!get_wow (process, is_wow, process_arch))
    {
      return FALSE;
    }

  const char *name;
  switch (process_arch)
  {
    case IMAGE_FILE_MACHINE_I386:
      name = "/usr/libexec/getprocaddr32.exe";
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      name = "/usr/libexec/getprocaddr64.exe";
      break;
    /* TODO: provide exes for these */
    case IMAGE_FILE_MACHINE_ARMNT:
      name = "/usr/libexec/getprocaddrarm32.exe";
      break;
    case IMAGE_FILE_MACHINE_ARM64:
      name = "/usr/libexec/getprocaddrarm64.exe";
      break;
    default:
      return FALSE; /* what?!? */
  }
  wchar_t wbuf[PATH_MAX];

  if (cygwin_conv_path (CCP_POSIX_TO_WIN_W, name, wbuf, sizeof (wbuf))
      || GetFileAttributesW (wbuf) == INVALID_FILE_ATTRIBUTES)
    return FALSE;

  STARTUPINFOW si = {};
  PROCESS_INFORMATION pi;
  WCHAR cmd[PATH_MAX + 128];
  WCHAR title[] = L"cygwin-console-helper";
  DWORD process_exit;

  int written = swprintf (cmd, sizeof (cmd) / sizeof (*cmd),
                          L"\"%ls\" %ls %d %u %u", wbuf, function_name,
                          exit_code, (unsigned int) pid,
                          (unsigned int) timeout_ms);
  if (written <= 0 || (size_t) written >= sizeof (cmd) / sizeof (*cmd))
    return FALSE;

  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.lpTitle = title;
  si.hStdInput = si.hStdError = si.hStdOutput = INVALID_HANDLE_VALUE;

  /* Create a new hidden process without leaking inheritable handles. */
  if (!CreateProcessW (NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL,
                       &si, &pi))
    {
      return FALSE;
    }

  DWORD wait_ms = (timeout_ms <= INFINITE - 2000) ? timeout_ms + 2000 : INFINITE;
  if (WaitForSingleObject (pi.hProcess, wait_ms) == WAIT_TIMEOUT)
    {
      TerminateProcess (pi.hProcess, 1);
      process_exit = 1;
    }
  else if (!GetExitCodeProcess (pi.hProcess, &process_exit))
    process_exit = (DWORD) -1;

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  return process_exit == 0 ? TRUE : FALSE;
}

static int current_is_wow = -1;
static int is_32_bit_os = -1;

typedef BOOL (WINAPI * IsWow64Process2_t) (HANDLE, USHORT *, USHORT *);
static bool wow64process2initialized = false;
static IsWow64Process2_t pIsWow64Process2 /* = NULL */;

typedef BOOL (WINAPI * GetProcessInformation_t) (HANDLE,
                                                 PROCESS_INFORMATION_CLASS,
                                                 LPVOID, DWORD);
static bool getprocessinfoinitialized = false;
static GetProcessInformation_t pGetProcessInformation /* = NULL */;

static BOOL
get_wow (HANDLE process, BOOL &is_wow, USHORT &process_arch)
{
  USHORT native_arch = IMAGE_FILE_MACHINE_UNKNOWN;
  if (!wow64process2initialized)
    {
      pIsWow64Process2 = (IsWow64Process2_t)
              GetProcAddress (GetModuleHandle ("KERNEL32"),
                              "IsWow64Process2");
      MemoryBarrier ();
      wow64process2initialized = true;
    }
  if (!pIsWow64Process2)
    {
      if (is_32_bit_os == -1)
        {
          SYSTEM_INFO info;

          GetNativeSystemInfo (&info);
          if (info.wProcessorArchitecture == 0)
            is_32_bit_os = 1;
          else if (info.wProcessorArchitecture == 9)
            is_32_bit_os = 0;
          else
            is_32_bit_os = -2;
        }

      if (current_is_wow == -1
          && !IsWow64Process (GetCurrentProcess (), &current_is_wow))
        current_is_wow = -2;

      if (is_32_bit_os == -2 || current_is_wow == -2)
        return FALSE;

      if (!IsWow64Process (process, &is_wow))
        return FALSE;

      process_arch = is_32_bit_os || is_wow ? IMAGE_FILE_MACHINE_I386 :
                                      IMAGE_FILE_MACHINE_AMD64;
      return TRUE;
    }

  if (!pIsWow64Process2 (process, &process_arch, &native_arch))
    return FALSE;

  /* The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process
   * is not a WOW64 process
   */
  if (process_arch == IMAGE_FILE_MACHINE_UNKNOWN)
    {
      struct /* _PROCESS_MACHINE_INFORMATION */
        {
          /* 0x0000 */ USHORT ProcessMachine;
          /* 0x0002 */ USHORT Res0;
          /* 0x0004 */ DWORD MachineAttributes;
        } /* size: 0x0008 */ process_machine_info;

      is_wow = FALSE;
      /* However, x86_64 on ARM64 claims not to be WOW64, so we have to
       * dig harder... */
      if (!getprocessinfoinitialized)
        {
          pGetProcessInformation = (GetProcessInformation_t)
                  GetProcAddress (GetModuleHandle ("KERNEL32"),
                                  "GetProcessInformation");
          MemoryBarrier ();
          getprocessinfoinitialized = true;
        }
      /*#define ProcessMachineTypeInfo 9*/
      if (pGetProcessInformation &&
          pGetProcessInformation (process, (PROCESS_INFORMATION_CLASS)9,
            &process_machine_info, sizeof (process_machine_info)))
        process_arch = process_machine_info.ProcessMachine;
      else
        process_arch = native_arch;
    }
  else
    {
      is_wow = TRUE;
    }
  return TRUE;
}

struct process_tree_node
{
  DWORD pid;
  ULONGLONG create_time;
  HANDLE process;
  pid_t cyg_pid;
};

static BOOL
get_process_create_time (HANDLE process, ULONGLONG &create_time)
{
  FILETIME creation, exit_time, kernel, user;
  if (!GetProcessTimes (process, &creation, &exit_time, &kernel, &user))
    return FALSE;
  ULARGE_INTEGER uli;
  uli.LowPart = creation.dwLowDateTime;
  uli.HighPart = creation.dwHighDateTime;
  create_time = uli.QuadPart;
  return TRUE;
}

static BOOL
is_process_active (HANDLE process)
{
  if (!process)
    return FALSE;
  DWORD wait_res = WaitForSingleObject (process, 0);
  if (wait_res == WAIT_OBJECT_0)
    return FALSE;
  if (wait_res == WAIT_TIMEOUT)
    return TRUE;
  /* Fallback when process handle lacks SYNCHRONIZE */
  DWORD code = 0;
  return !GetExitCodeProcess (process, &code) || code == STILL_ACTIVE;
}

static pid_t
resolve_msys_pid (DWORD winpid, bool &has_msys_parent, bool &is_overlay_stub)
{
  has_msys_parent = false;
  is_overlay_stub = false;
  pid_t cyg_pid = cygwin_winpid_to_pid (winpid);
  if (cyg_pid <= -1)
    return -1;
  DWORD state, proc_winpid;
#ifdef __INSIDE_CYGWIN__
  pinfo p (cyg_pid);
  if (!p)
    return -1;
  state = p->process_state;
  proc_winpid = p->dwProcessId;
#else
  external_pinfo *ep =
    (external_pinfo *) cygwin_internal (CW_GETPINFO, cyg_pid);
  if (!ep)
    return -1;
  state = ep->process_state;
  proc_winpid = ep->dwProcessId;
#endif
  if (state & PID_NOTCYGWIN)
    {
      if (proc_winpid == winpid)
        has_msys_parent = true;
      else
        /* Brief _P_OVERLAY window in spawn.cc after myself->dwProcessId is
         * updated to the child's WinPID but before NtClose(old_winpid_hdl)
         * removes the stub's winpid.<pid> symlink; complements has_msys_parent. */
        is_overlay_stub = true;
      return -1;
    }
  if (state & PID_CYGPARENT)
    has_msys_parent = true;
  return cyg_pid;
}

static void
signal_msys_node (const process_tree_node *nodes, int idx, int signo)
{
  pid_t cyg_pid = nodes[idx].cyg_pid;
  if (cyg_pid <= -1)
    return;
  kill (cyg_pid, signo);
}

static void
wait_for_win32_nodes (const process_tree_node *nodes, int start_idx,
                      int len, DWORD max_wait_ms)
{
  if (max_wait_ms == 0 || start_idx >= len)
    return;

  ULONGLONG deadline = GetTickCount64 () + max_wait_ms;
  int idx = start_idx;
  while (idx < len)
    {
      HANDLE batch[MAXIMUM_WAIT_OBJECTS];
      DWORD count = 0;
      while (idx < len && count < MAXIMUM_WAIT_OBJECTS)
        {
          if (nodes[idx].cyg_pid < 0 && nodes[idx].process
              && is_process_active (nodes[idx].process))
            batch[count++] = nodes[idx].process;
          idx++;
        }
      if (count == 0)
        continue;

      ULONGLONG now = GetTickCount64 ();
      if (now >= deadline)
        break;
      DWORD rem = (DWORD) (deadline - now);
      if (WaitForMultipleObjects (count, batch, TRUE, rem) == WAIT_FAILED)
        {
          for (DWORD j = 0; j < count; j++)
            {
              now = GetTickCount64 ();
              if (now >= deadline)
                break;
              WaitForSingleObject (batch[j], (DWORD) (deadline - now));
            }
        }
    }
}

static int
terminate_win32_nodes (const process_tree_node *nodes, int len, int exit_code)
{
  int ret = 0;
  bool any_terminated = false;
  for (int i = 0; i < len; i++)
    {
      if (nodes[i].cyg_pid < 0 && is_process_active (nodes[i].process))
        {
          if (TerminateProcess (nodes[i].process, exit_code))
            any_terminated = true;
          else if (is_process_active (nodes[i].process))
            ret = -1;
        }
    }
  if (any_terminated)
    wait_for_win32_nodes (nodes, 0, len, 500);
  return ret;
}

/**
 * Signals or terminates the process corresponding to main_process and all of
 * its directly and indirectly spawned subprocesses in top-down order.
 */
static int
exit_process_tree (HANDLE main_process, int exit_code)
{
  int signo = exit_code & 0x7f;
  DWORD root_pid = GetProcessId (main_process);
  if (root_pid == 0)
    {
      if (signo == SIGINT || signo == SIGQUIT)
        return -1;
      return TerminateProcess (main_process, exit_code) ? 0 : -1;
    }

  ULONGLONG root_create_time = 0;
  BOOL have_root_time = get_process_create_time (main_process, root_create_time);

  const int max_cap = 16384;
  int cap = 256;
  HANDLE heap = GetProcessHeap ();
  process_tree_node *nodes = (process_tree_node *)
    HeapAlloc (heap, 0, cap * sizeof (process_tree_node));
  if (!nodes)
    {
      if (signo == SIGINT || signo == SIGQUIT)
        return -1;
      return TerminateProcess (main_process, exit_code) ? 0 : -1;
    }

  nodes[0].pid = root_pid;
  nodes[0].create_time = root_create_time;
  nodes[0].process = main_process;
  nodes[0].cyg_pid = -1;
  int len = 1;
  int i, ret = 0;

  HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE)
    {
      PROCESSENTRY32 entry;
      DWORD self_pid = GetCurrentProcessId ();

      /*
       * Even if Process32First()/Process32Next() seem to traverse the
       * processes in topological order (i.e. parent processes before
       * child processes), there is nothing in the Win32 API documentation
       * suggesting that this is guaranteed.
       *
       * Therefore, run through them at least twice and stop when no more
       * process nodes were added to the list. Because nodes[0] is root_pid
       * and children are only appended after their parent is already present,
       * nodes[0 .. len - 1] is guaranteed to be topologically ordered
       * (parents before children).
       */
      for (;;)
        {
          memset (&entry, 0, sizeof (entry));
          entry.dwSize = sizeof (entry);

          if (!Process32First (snapshot, &entry))
            break;

          int orig_len = len;
          do
            {
              if (entry.th32ProcessID == 0 || entry.th32ProcessID == self_pid)
                continue;

              bool already_added = false;
              int parent_idx = -1;
              for (i = 0; i < len; i++)
                {
                  if (nodes[i].pid == entry.th32ProcessID)
                    {
                      already_added = true;
                      break;
                    }
                  if (nodes[i].pid == entry.th32ParentProcessID)
                    parent_idx = i;
                }

              if (already_added || parent_idx < 0)
                continue;

              HANDLE hchild = OpenProcess (
                  PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
                      | SYNCHRONIZE,
                  FALSE, entry.th32ProcessID);
              if (!hchild)
                hchild = OpenProcess (
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    FALSE, entry.th32ProcessID);
              if (!hchild)
                hchild = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, entry.th32ProcessID);
              if (!hchild)
                continue;

              /* Reject stale th32ParentProcessID matches caused by PID reuse */
              ULONGLONG child_create_time = 0;
              if (!get_process_create_time (hchild, child_create_time)
                  || ((parent_idx > 0 || have_root_time)
                      && child_create_time < nodes[parent_idx].create_time))
                {
                  CloseHandle (hchild);
                  continue;
                }

              if (len == cap)
                {
                  if (cap >= max_cap)
                    {
                      CloseHandle (hchild);
                      break;
                    }
                  int new_cap = cap * 2;
                  if (new_cap > max_cap)
                    new_cap = max_cap;
                  process_tree_node *grown = (process_tree_node *)
                    HeapReAlloc (heap, 0, nodes,
                                 new_cap * sizeof (process_tree_node));
                  if (!grown)
                    {
                      CloseHandle (hchild);
                      break;
                    }
                  nodes = grown;
                  cap = new_cap;
                }

              /* Is this descendant an MSYS2 process?
               * Note that MSYS2 also creates pinfo entries (flagged with
               * PID_NOTCYGWIN) and winpid.<pid> symlinks for native Win32
               * children it spawns. Those children must be treated as native
               * Win32 nodes so they receive CtrlRoutine / TerminateProcess.
               * Furthermore, if an MSYS2 parent spawned this child (Win32 or
               * MSYS2) via _P_OVERLAY (execve), the MSYS2 stub transferred its
               * winpid symlink to the child (leaving nodes[parent_idx].cyg_pid
               * == -1); release nodes[parent_idx].process so the stub is not
               * killed before its captive child exits. */
              bool has_msys_parent = false;
              bool is_overlay_stub = false;
              pid_t cyg_pid = resolve_msys_pid (entry.th32ProcessID,
                                                has_msys_parent,
                                                is_overlay_stub);
              if (has_msys_parent && parent_idx > 0
                  && nodes[parent_idx].cyg_pid < 0
                  && nodes[parent_idx].process)
                {
                  CloseHandle (nodes[parent_idx].process);
                  nodes[parent_idx].process = NULL;
                }
              if (cyg_pid > -1 || is_overlay_stub)
                {
                  CloseHandle (hchild);
                  hchild = NULL;
                }

              /* Keep hchild open for Win32 nodes so Windows cannot recycle
               * its PID mid-sweep. */
              nodes[len].pid = entry.th32ProcessID;
              nodes[len].create_time = child_create_time;
              nodes[len].process = hchild;
              nodes[len].cyg_pid = cyg_pid;
              len++;
            }
          while (len < max_cap && Process32Next (snapshot, &entry));

          if (orig_len == len || len >= max_cap)
            break;
        }

      CloseHandle (snapshot);
    }

  switch (signo)
    {
    case SIGINT:
    case SIGQUIT:
      {
        DWORD ctrl_event = (signo == SIGINT) ? CTRL_C_EVENT : CTRL_BREAK_EVENT;
        const DWORD helper_timeout_ms = 5000;
        const DWORD coordinator_grace_ms = 200;

        if (is_process_active (nodes[0].process))
          kill_via_console_helper (nodes[0].process, L"CtrlRoutine",
                                   ctrl_event, nodes[0].pid,
                                   helper_timeout_ms);

        ULONGLONG settle_start = GetTickCount64 ();
        WaitForSingleObject (nodes[0].process, coordinator_grace_ms);
        if (len > 1)
          {
            ULONGLONG elapsed = GetTickCount64 () - settle_start;
            if (elapsed < coordinator_grace_ms)
              wait_for_win32_nodes (nodes, 1, len,
                                    (DWORD) (coordinator_grace_ms - elapsed));

            for (i = 1; i < len; i++)
              {
                if (nodes[i].cyg_pid > -1)
                  {
                    signal_msys_node (nodes, i, signo);
                  }
                else if (is_process_active (nodes[i].process))
                  {
                    kill_via_console_helper (nodes[i].process, L"CtrlRoutine",
                                             ctrl_event, nodes[i].pid,
                                             helper_timeout_ms);
                  }
              }
          }
        break;
      }

    case SIGTERM:
      {
        const DWORD term_grace_ms = 500;
        const DWORD coordinator_grace_ms = 200;

        /* Phase 1: Top-down graceful CTRL_BREAK_EVENT within shared 500ms
         * post-signal grace budget. */
        for (i = 0; i < len; i++)
          {
            if (nodes[i].cyg_pid > -1)
              signal_msys_node (nodes, i, signo);
          }

        ULONGLONG deadline = 0;
        bool deadline_set = false;

        for (i = 0; i < len; i++)
          {
            if (nodes[i].cyg_pid > -1 || !is_process_active (nodes[i].process))
              continue;

            DWORD helper_wait = term_grace_ms;
            if (deadline_set)
              {
                ULONGLONG now = GetTickCount64 ();
                if (now >= deadline)
                  break;
                helper_wait = (DWORD) (deadline - now);
              }

            ULONGLONG call_start = GetTickCount64 ();
            BOOL ok = kill_via_console_helper (nodes[i].process, L"CtrlRoutine",
                                               CTRL_BREAK_EVENT, nodes[i].pid,
                                               helper_wait);
            if (!deadline_set)
              {
                /* Start the 500ms post-signal grace budget after nodes[0] is
                 * signaled; if nodes[0] injection failed, count elapsed time
                 * since call_start so remaining descendants still receive the
                 * rest of the 500ms grace window. */
                deadline = (ok ? GetTickCount64 () : call_start) + term_grace_ms;
                deadline_set = true;
              }

            /* Coordinator-first two-stage settle wait: give nodes[0] up to
             * coordinator_grace_ms (200ms) to handle CTRL_BREAK_EVENT, and if
             * it exits, give descendants a capped settle window to finish
             * coordinator-initiated shutdown before injecting CtrlRoutine into
             * children, while preserving budget within term_grace_ms (500ms). */
            if (ok && i == 0)
              {
                ULONGLONG now = GetTickCount64 ();
                if (now < deadline)
                  {
                    DWORD first_wait = (DWORD) (deadline - now);
                    if (len > 1 && first_wait > coordinator_grace_ms)
                      first_wait = coordinator_grace_ms;
                    WaitForSingleObject (nodes[0].process, first_wait);
                  }
                if (len > 1 && !is_process_active (nodes[0].process))
                  {
                    now = GetTickCount64 ();
                    if (now < deadline)
                      {
                        DWORD settle = (DWORD) (deadline - now);
                        if (settle > coordinator_grace_ms)
                          settle = coordinator_grace_ms;
                        wait_for_win32_nodes (nodes, 1, len, settle);
                      }
                  }
              }
          }

        if (deadline_set)
          {
            ULONGLONG now = GetTickCount64 ();
            if (now < deadline)
              wait_for_win32_nodes (nodes, 0, len, (DWORD) (deadline - now));
          }

        /* Phase 2: Top-down forced TerminateProcess sweep of any survivors */
        ret = terminate_win32_nodes (nodes, len, exit_code);
        break;
      }

    default:
      {
        for (i = 0; i < len; i++)
          {
            if (nodes[i].cyg_pid > -1)
              signal_msys_node (nodes, i, signo);
          }
        ret = terminate_win32_nodes (nodes, len, exit_code);
        break;
      }
    }

  for (i = 1; i < len; i++)
    if (nodes[i].process)
      CloseHandle (nodes[i].process);

  HeapFree (heap, 0, nodes);
  return ret;
}

#endif
