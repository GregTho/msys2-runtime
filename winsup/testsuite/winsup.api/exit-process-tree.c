/* exit-process-tree.c: End-to-end tests for exit_process_tree(),
   getprocaddr*.exe CtrlRoutine injection, sigExeced synchronization,
   and kill -f -W handling on multi-process Win32 trees.

   This file is part of Cygwin / MSYS2.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for details. */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <process.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cygwin.h>
#include <sys/wait.h>
#include <unistd.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static char g_suite_dir[PATH_MAX];
static char g_self_win[PATH_MAX];
static char g_helper_posix[PATH_MAX];
static char g_helper_win[PATH_MAX];
static char g_kill_posix[PATH_MAX];

static int
init_paths (void)
{
  char self_path[PATH_MAX];
  ssize_t n = readlink ("/proc/self/exe", self_path, sizeof (self_path) - 1);
  if (n <= 0)
    {
      perror ("readlink(/proc/self/exe)");
      return -1;
    }
  self_path[n] = '\0';

  if (cygwin_conv_path (CCP_POSIX_TO_WIN_A, self_path,
                        g_self_win, sizeof (g_self_win)) != 0)
    {
      perror ("cygwin_conv_path(self)");
      return -1;
    }

  /* Strip binary name (winsup.api/exit-process-tree.exe) and winsup.api dir */
  char *slash = strrchr (self_path, '/');
  if (!slash)
    return -1;
  *slash = '\0';
  slash = strrchr (self_path, '/');
  if (!slash)
    return -1;
  *slash = '\0';

  int written = snprintf (g_suite_dir, sizeof (g_suite_dir), "%s", self_path);
  if (written <= 0 || (size_t) written >= sizeof (g_suite_dir))
    return -1;
  written = snprintf (g_helper_posix, sizeof (g_helper_posix),
                      "%s/mingw/win32-proctree.exe", g_suite_dir);
  if (written <= 0 || (size_t) written >= sizeof (g_helper_posix))
    return -1;
  if (access (g_helper_posix, X_OK) != 0)
    {
      fprintf (stderr, "Helper binary missing or not executable: %s\n",
               g_helper_posix);
      return -1;
    }

  if (cygwin_conv_path (CCP_POSIX_TO_WIN_A, g_helper_posix,
                        g_helper_win, sizeof (g_helper_win)) != 0)
    {
      perror ("cygwin_conv_path(helper)");
      return -1;
    }

  if (access ("/usr/libexec/getprocaddr64.exe", F_OK) != 0
      && access ("/usr/libexec/getprocaddr32.exe", F_OK) != 0)
    {
      fprintf (stderr,
               "Console helper missing in testinst: /usr/libexec/getprocaddr*.exe\n");
      return -1;
    }

  written = snprintf (g_kill_posix, sizeof (g_kill_posix),
                      "%s/../utils/kill.exe", g_suite_dir);
  if (written <= 0 || (size_t) written >= sizeof (g_kill_posix))
    return -1;
  return 0;
}

static int
make_marker_paths (const char *tag, char *posix_buf, size_t posix_sz,
                   char *win_buf, size_t win_sz)
{
  int written = snprintf (posix_buf, posix_sz, "%s/exit-proctree-%d-%s.tmp",
                          g_suite_dir, (int) getpid (), tag);
  if (written <= 0 || (size_t) written >= posix_sz)
    return -1;
  unlink (posix_buf);
  if (cygwin_conv_path (CCP_POSIX_TO_WIN_A, posix_buf, win_buf, win_sz) != 0)
    {
      perror ("cygwin_conv_path(marker)");
      return -1;
    }
  return 0;
}

static int
read_line_timeout (int fd, char *buf, size_t cap, DWORD timeout_ms)
{
  if (cap == 0)
    return -1;

  int flags = fcntl (fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl (fd, F_SETFL, flags | O_NONBLOCK);

  ULONGLONG deadline = GetTickCount64 () + timeout_ms;
  size_t pos = 0;

  while (pos + 1 < cap)
    {
      char ch;
      ssize_t r = read (fd, &ch, 1);
      if (r == 1)
        {
          if (ch == '\r')
            continue;
          if (ch == '\n')
            {
              buf[pos] = '\0';
              return 0;
            }
          buf[pos++] = ch;
          continue;
        }
      if (r == 0)
        break;
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        return -1;
      if (GetTickCount64 () >= deadline)
        return -1;
      Sleep (10);
    }

  buf[pos] = '\0';
  return pos > 0 ? 0 : -1;
}

static pid_t
waitpid_timeout (pid_t pid, int *status, DWORD timeout_ms)
{
  ULONGLONG deadline = GetTickCount64 () + timeout_ms;
  for (;;)
    {
      pid_t w = waitpid (pid, status, WNOHANG);
      if (w != 0)
        return w;
      if (GetTickCount64 () >= deadline)
        return 0;
      Sleep (10);
    }
}

static int
read_marker_file (const char *posix_path, char *buf, size_t cap)
{
  int fd = open (posix_path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t total = 0;
  while ((size_t) total + 1 < cap)
    {
      ssize_t r = read (fd, buf + total, cap - 1 - (size_t) total);
      if (r > 0)
        total += r;
      else if (r == 0)
        break;
      else if (errno != EINTR)
        {
          close (fd);
          return -1;
        }
    }
  close (fd);
  buf[total] = '\0';
  return (int) total;
}

static pid_t
spawn_captive_proctree_args (const char *mode, const char *marker_win,
                             const char *arg3, const char *arg4, int *out_rfd)
{
  int pfd[2];
  if (pipe (pfd) != 0)
    {
      perror ("pipe");
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      perror ("fork");
      close (pfd[0]);
      close (pfd[1]);
      return -1;
    }

  if (pid == 0)
    {
      close (pfd[0]);
      setsid ();
      int null_fd = open ("/dev/null", O_RDONLY);
      if (null_fd >= 0 && null_fd != STDIN_FILENO)
        {
          dup2 (null_fd, STDIN_FILENO);
          close (null_fd);
        }
      if (pfd[1] != STDOUT_FILENO)
        {
          dup2 (pfd[1], STDOUT_FILENO);
          close (pfd[1]);
        }
      const char *argv[] = {
        "win32-proctree", mode, marker_win, arg3, arg4, NULL
      };
      execv (g_helper_posix, (char *const *) argv);
      _exit (127);
    }

  close (pfd[1]);
  *out_rfd = pfd[0];
  return pid;
}

static pid_t
spawn_captive_proctree (const char *mode, const char *marker_win, int *out_rfd)
{
  return spawn_captive_proctree_args (mode, marker_win, NULL, NULL, out_rfd);
}

static HANDLE
open_win32_pid (unsigned long winpid)
{
  if (winpid == 0)
    return NULL;
  return OpenProcess (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
                      | PROCESS_TERMINATE,
                      FALSE, (DWORD) winpid);
}

static int
open_win32_pids (const char *tag, const unsigned long *pids,
                 HANDLE *handles, int count)
{
  for (int i = 0; i < count; i++)
    {
      handles[i] = open_win32_pid (pids[i]);
      if (!handles[i])
        {
          fprintf (stderr, "%s: OpenProcess(%lu) failed: %lu\n",
                   tag, pids[i], (unsigned long) GetLastError ());
          return -1;
        }
    }
  return 0;
}

static void
cleanup_case (pid_t msys_pid, int pipe_fd, HANDLE handles[3],
              const char *marker_posix)
{
  if (pipe_fd >= 0)
    close (pipe_fd);

  for (int i = 0; i < 3; i++)
    {
      if (handles[i] != NULL)
        {
          if (WaitForSingleObject (handles[i], 0) == WAIT_TIMEOUT)
            {
              TerminateProcess (handles[i], 99);
              WaitForSingleObject (handles[i], 2000);
            }
          CloseHandle (handles[i]);
          handles[i] = NULL;
        }
    }

  if (msys_pid > 0)
    {
      int st = 0;
      if (waitpid (msys_pid, &st, WNOHANG) == 0)
        {
          kill (msys_pid, SIGKILL);
          waitpid_timeout (msys_pid, &st, 3000);
        }
    }

  if (marker_posix && marker_posix[0])
    unlink (marker_posix);
}

/* 1. Multi-threaded Win32 target holding a lock whose SetConsoleCtrlHandler
 *    blocks on the CtrlRoutine thread while main() releases the lock, writes
 *    MT_CLEAN_OK, and calls ExitProcess(0). Verifies:
 *    - No ExitProcess remote-thread injection (lock holder shuts down cleanly)
 *    - getprocaddr WaitForMultipleObjects({hProcess, hThread}) returns promptly
 *    - waitpid() reports WIFSIGNALED && WTERMSIG == SIGTERM. */
static int
test_mt_graceful_sigterm (void)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128], marker[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long root_pid = 0;
  DWORD win_ec = 99;

  if (make_marker_paths ("mt-term", marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree ("mt-graceful-term", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu", &root_pid) != 1)
    {
      fprintf (stderr, "mt-graceful-term failed to report READY (got '%s')\n",
               line);
      goto out;
    }

  if (open_win32_pids ("mt-graceful-term", &root_pid, &handles[0], 1) != 0)
    goto out;

  ULONGLONG t0 = GetTickCount64 ();
  if (kill (pid, SIGTERM) != 0)
    {
      perror ("kill(SIGTERM)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 5000) != pid)
    {
      fprintf (stderr, "mt-graceful-term waitpid timed out\n");
      goto out;
    }
  pid = -1;

  ULONGLONG elapsed = GetTickCount64 () - t0;
  if (elapsed >= 4500)
    {
      fprintf (stderr,
               "mt-graceful-term took %llu ms (expected prompt exit < 4500 ms)\n",
               (unsigned long long) elapsed);
      goto out;
    }

  if (!WIFSIGNALED (status) || WTERMSIG (status) != SIGTERM)
    {
      fprintf (stderr,
               "mt-graceful-term unexpected waitpid status 0x%x (expected SIGTERM)\n",
               (unsigned int) status);
      goto out;
    }

  if (WaitForSingleObject (handles[0], 2000) != WAIT_OBJECT_0
      || !GetExitCodeProcess (handles[0], &win_ec) || win_ec != 0)
    {
      fprintf (stderr,
               "mt-graceful-term Win32 exit code = %lu (expected 0)\n",
               (unsigned long) win_ec);
      goto out;
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strcmp (marker, "MT_CLEAN_OK\n") != 0)
    {
      fprintf (stderr, "mt-graceful-term bad marker '%s'\n", marker);
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

/* 2 & 3. 3-level Win32 process tree (coordinator -> worker -> leaf) signaled
 *        with SIGINT or SIGTERM. Workers fail with exit code 99 if hit by
 *        CtrlRoutine before the coordinator signals graceful pipe shutdown.
 *        Verifies top-down delivery + settle window + clean waitpid status. */
static int
test_tree_top_down_signal (int signo, const char *tag)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128], marker[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long pids[3] = { 0, 0, 0 };

  if (make_marker_paths (tag, marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree ("tree-coord", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu %lu %lu",
                 &pids[0], &pids[1], &pids[2]) != 3)
    {
      fprintf (stderr, "%s: failed to read 3 READY pids (got '%s')\n",
               tag, line);
      goto out;
    }

  if (open_win32_pids (tag, pids, handles, 3) != 0)
    goto out;

  ULONGLONG t0 = GetTickCount64 ();
  if (kill (pid, signo) != 0)
    {
      perror ("kill(tree-coord)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 5000) != pid)
    {
      fprintf (stderr, "%s: waitpid timed out\n", tag);
      goto out;
    }
  pid = -1;

  ULONGLONG elapsed = GetTickCount64 () - t0;
  if (elapsed >= 4500)
    {
      fprintf (stderr, "%s: took %llu ms (expected < 4500 ms)\n",
               tag, (unsigned long long) elapsed);
      goto out;
    }

  if (!WIFSIGNALED (status) || WTERMSIG (status) != signo)
    {
      fprintf (stderr,
               "%s: unexpected waitpid status 0x%x (expected sig %d)\n",
               tag, (unsigned int) status, signo);
      goto out;
    }

  for (int i = 0; i < 3; i++)
    {
      DWORD win_ec = 99;
      if (WaitForSingleObject (handles[i], 2000) != WAIT_OBJECT_0
          || !GetExitCodeProcess (handles[i], &win_ec) || win_ec != 0)
        {
          fprintf (stderr,
                   "%s: node[%d] (pid %lu) Win32 exit code = %lu (expected 0)\n",
                   tag, i, pids[i], (unsigned long) win_ec);
          goto out;
        }
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strcmp (marker, "TREE_ORDER_OK\n") != 0)
    {
      fprintf (stderr, "%s: unexpected marker '%s'\n", tag, marker);
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

/* 4. Interactive REPL catching CTRL_C_EVENT without exiting:
 *    - Survives multiple SIGINT signals (no ExitProcess/TerminateProcess)
 *    - Receives exactly one CTRL_C_EVENT per kill(pid, SIGINT) (no sigq retry loop)
 *    - Cleanly exits on SIGQUIT (CTRL_BREAK_EVENT) with WTERMSIG == SIGQUIT. */
static int
test_repl_sigint_survival_and_sigquit (void)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128], marker[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long root_pid = 0;
  DWORD win_ec = 99;

  if (make_marker_paths ("repl", marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree ("repl", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu", &root_pid) != 1)
    {
      fprintf (stderr, "repl: failed to read READY (got '%s')\n", line);
      goto out;
    }

  if (open_win32_pids ("repl", &root_pid, &handles[0], 1) != 0)
    goto out;

  for (int attempt = 1; attempt <= 2; attempt++)
    {
      char expected[32];
      snprintf (expected, sizeof (expected), "SIGINT %d", attempt);

      if (kill (pid, SIGINT) != 0)
        {
          perror ("kill(repl, SIGINT)");
          goto out;
        }
      if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
          || strcmp (line, expected) != 0)
        {
          fprintf (stderr, "repl: expected '%s', got '%s'\n", expected, line);
          goto out;
        }

      /* Wait > 200ms so spawn.cc's 100ms cygwait loop runs and verify
       * neither the Win32 target nor the MSYS2 stub exited or re-queued SIGINT. */
      Sleep (300);
      if (WaitForSingleObject (handles[0], 0) != WAIT_TIMEOUT)
        {
          fprintf (stderr, "repl: Win32 target died on SIGINT #%d\n", attempt);
          goto out;
        }
      if (waitpid (pid, &status, WNOHANG) != 0)
        {
          fprintf (stderr, "repl: MSYS2 stub exited on SIGINT #%d\n", attempt);
          pid = -1;
          goto out;
        }
    }

  if (kill (pid, SIGQUIT) != 0)
    {
      perror ("kill(repl, SIGQUIT)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 5000) != pid)
    {
      fprintf (stderr, "repl: waitpid after SIGQUIT timed out\n");
      goto out;
    }
  pid = -1;

  if (!WIFSIGNALED (status) || WTERMSIG (status) != SIGQUIT)
    {
      fprintf (stderr,
               "repl: unexpected waitpid status 0x%x (expected SIGQUIT)\n",
               (unsigned int) status);
      goto out;
    }

  if (WaitForSingleObject (handles[0], 2000) != WAIT_OBJECT_0
      || !GetExitCodeProcess (handles[0], &win_ec) || win_ec != 0)
    {
      fprintf (stderr, "repl: unexpected Win32 exit code %lu\n",
               (unsigned long) win_ec);
      goto out;
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strcmp (marker, "SIGINT_COUNT=2\n") != 0)
    {
      fprintf (stderr, "repl: unexpected marker '%s'\n", marker);
      goto out;
    }

  cleanup_case (pid, rfd, handles, marker_posix);
  rfd = -1;

  /* Also verify that when a captive Win32 process (with stdio redirected)
   * catches SIGINT and later exits normally via ExitProcess(0), spawn.cc
   * clears sigExeced so waitpid() reports WIFEXITED && WEXITSTATUS == 0. */
  pid = spawn_captive_proctree ("repl-normal-exit", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu", &root_pid) != 1)
    {
      fprintf (stderr, "repl-normal-exit: failed to read READY (got '%s')\n",
               line);
      goto out;
    }

  if (open_win32_pids ("repl-normal-exit", &root_pid, &handles[0], 1) != 0)
    goto out;

  if (kill (pid, SIGINT) != 0)
    {
      perror ("kill(repl-normal-exit, SIGINT)");
      goto out;
    }
  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || strcmp (line, "SIGINT 1") != 0)
    {
      fprintf (stderr, "repl-normal-exit: expected 'SIGINT 1', got '%s'\n",
               line);
      goto out;
    }

  if (waitpid_timeout (pid, &status, 5000) != pid)
    {
      fprintf (stderr, "repl-normal-exit: waitpid timed out\n");
      goto out;
    }
  pid = -1;

  if (!WIFEXITED (status) || WEXITSTATUS (status) != 0)
    {
      fprintf (stderr,
               "repl-normal-exit: unexpected waitpid status 0x%x (expected normal exit 0)\n",
               (unsigned int) status);
      goto out;
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strcmp (marker, "REPL_NORMAL_EXIT\n") != 0)
    {
      fprintf (stderr, "repl-normal-exit: unexpected marker '%s'\n", marker);
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

/* 5. Stubborn 3-level Win32 tree ignoring CTRL_BREAK_EVENT on SIGTERM:
 *    - Phase 1 delivers CTRL_BREAK_EVENT (verified via GOT_BREAK marker)
 *    - After ~500ms grace budget expires, Phase 2 sweeps all 3 nodes with
 *      TerminateProcess(..., 128 + SIGTERM) before waitpid() returns. */
static int
test_stubborn_tree_sigterm_fallback (void)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128], marker[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long pids[3] = { 0, 0, 0 };

  if (make_marker_paths ("stubborn-term", marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree ("stubborn-tree", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu %lu %lu",
                 &pids[0], &pids[1], &pids[2]) != 3)
    {
      fprintf (stderr, "stubborn-term: failed to read READY (got '%s')\n",
               line);
      goto out;
    }

  if (open_win32_pids ("stubborn-term", pids, handles, 3) != 0)
    goto out;

  ULONGLONG t0 = GetTickCount64 ();
  if (kill (pid, SIGTERM) != 0)
    {
      perror ("kill(stubborn-tree, SIGTERM)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 8000) != pid)
    {
      fprintf (stderr, "stubborn-term: waitpid timed out\n");
      goto out;
    }
  pid = -1;

  ULONGLONG elapsed = GetTickCount64 () - t0;
  if (elapsed < 400 || elapsed >= 8000)
    {
      fprintf (stderr,
               "stubborn-term: unexpected elapsed time %llu ms (expected ~500ms grace)\n",
               (unsigned long long) elapsed);
      goto out;
    }

  if (!WIFSIGNALED (status) || WTERMSIG (status) != SIGTERM)
    {
      fprintf (stderr,
               "stubborn-term: unexpected waitpid status 0x%x (expected SIGTERM)\n",
               (unsigned int) status);
      goto out;
    }

  for (int i = 0; i < 3; i++)
    {
      DWORD win_ec = 0;
      if (WaitForSingleObject (handles[i], 2000) != WAIT_OBJECT_0
          || !GetExitCodeProcess (handles[i], &win_ec)
          || win_ec != (DWORD) (128 + SIGTERM))
        {
          fprintf (stderr,
                   "stubborn-term: node[%d] exit code = %lu (expected %d)\n",
                   i, (unsigned long) win_ec, 128 + SIGTERM);
          goto out;
        }
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strstr (marker, "GOT_BREAK\n") == NULL)
    {
      fprintf (stderr, "stubborn-term: missing GOT_BREAK in marker '%s'\n",
               marker);
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

/* 6a. SIGKILL immediately terminates all 3 Win32 nodes with TerminateProcess
 *     without running CtrlRoutine handlers. */
static int
test_stubborn_tree_sigkill (void)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long pids[3] = { 0, 0, 0 };

  if (make_marker_paths ("stubborn-kill", marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree ("stubborn-tree", marker_win, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu %lu %lu",
                 &pids[0], &pids[1], &pids[2]) != 3)
    {
      fprintf (stderr, "stubborn-kill: failed to read READY (got '%s')\n",
               line);
      goto out;
    }

  if (open_win32_pids ("stubborn-kill", pids, handles, 3) != 0)
    goto out;

  if (kill (pid, SIGKILL) != 0)
    {
      perror ("kill(stubborn-tree, SIGKILL)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 5000) != pid)
    {
      fprintf (stderr, "stubborn-kill: waitpid timed out\n");
      goto out;
    }
  pid = -1;

  if (!WIFSIGNALED (status) || WTERMSIG (status) != SIGKILL)
    {
      fprintf (stderr,
               "stubborn-kill: unexpected waitpid status 0x%x (expected SIGKILL)\n",
               (unsigned int) status);
      goto out;
    }

  for (int i = 0; i < 3; i++)
    {
      DWORD win_ec = 0;
      if (WaitForSingleObject (handles[i], 2000) != WAIT_OBJECT_0
          || !GetExitCodeProcess (handles[i], &win_ec)
          || win_ec != (DWORD) (128 + SIGKILL))
        {
          fprintf (stderr,
                   "stubborn-kill: node[%d] exit code = %lu (expected %d)\n",
                   i, (unsigned long) win_ec, 128 + SIGKILL);
          goto out;
        }
    }

  if (access (marker_posix, F_OK) == 0)
    {
      fprintf (stderr, "stubborn-kill: CtrlRoutine unexpectedly ran on SIGKILL\n");
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

/* 6b. Standalone Win32 process tree terminated via `kill.exe -f -s TERM -W <winpid>`
 *     exercising winsup/utils/kill.cc forcekill() directly. */
static int
test_kill_util_force_winpid (void)
{
  if (access (g_kill_posix, X_OK) != 0)
    return 0;

  char marker_posix[PATH_MAX], marker_win[PATH_MAX];
  char cmdline[PATH_MAX * 2 + 64], line[128], marker[128], pid_arg[32];
  HANDLE handles[3] = { NULL, NULL, NULL };
  HANDLE pipe_rd = NULL, pipe_wr = NULL;
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  unsigned long pids[3] = { 0, 0, 0 };
  int rc = 1;

  if (make_marker_paths ("kill-util", marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  memset (&sa, 0, sizeof (sa));
  sa.nLength = sizeof (sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe (&pipe_rd, &pipe_wr, &sa, 0))
    return 1;
  SetHandleInformation (pipe_rd, HANDLE_FLAG_INHERIT, 0);

  int cmd_len = snprintf (cmdline, sizeof (cmdline), "\"%s\" tree-coord \"%s\"",
                          g_helper_win, marker_win);
  if (cmd_len <= 0 || (size_t) cmd_len >= sizeof (cmdline))
    {
      CloseHandle (pipe_rd);
      CloseHandle (pipe_wr);
      unlink (marker_posix);
      return 1;
    }
  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = INVALID_HANDLE_VALUE;
  si.hStdOutput = pipe_wr;
  si.hStdError = INVALID_HANDLE_VALUE;
  memset (&pi, 0, sizeof (pi));

  if (!CreateProcessA (g_helper_win, cmdline, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
      fprintf (stderr, "kill-util: CreateProcessA failed: %lu\n",
               (unsigned long) GetLastError ());
      CloseHandle (pipe_rd);
      CloseHandle (pipe_wr);
      unlink (marker_posix);
      return 1;
    }
  CloseHandle (pi.hThread);
  CloseHandle (pipe_wr);
  pipe_wr = NULL;
  handles[0] = pi.hProcess;

  /* Read READY line from pipe_rd */
  size_t pos = 0;
  ULONGLONG deadline = GetTickCount64 () + 5000;
  while (pos + 1 < sizeof (line) && GetTickCount64 () < deadline)
    {
      DWORD avail = 0;
      if (!PeekNamedPipe (pipe_rd, NULL, 0, NULL, &avail, NULL))
        break;
      if (avail == 0)
        {
          Sleep (10);
          continue;
        }
      char ch = 0;
      DWORD got = 0;
      if (!ReadFile (pipe_rd, &ch, 1, &got, NULL) || got == 0)
        break;
      if (ch == '\r')
        continue;
      if (ch == '\n')
        break;
      line[pos++] = ch;
    }
  line[pos] = '\0';
  CloseHandle (pipe_rd);
  pipe_rd = NULL;

  if (sscanf (line, "READY %lu %lu %lu", &pids[0], &pids[1], &pids[2]) != 3)
    {
      fprintf (stderr, "kill-util: failed to read READY (got '%s')\n", line);
      goto out;
    }

  if (open_win32_pids ("kill-util", &pids[1], &handles[1], 2) != 0)
    goto out;

  snprintf (pid_arg, sizeof (pid_arg), "%lu", pids[0]);
  pid_t kpid = fork ();
  if (kpid < 0)
    goto out;
  if (kpid == 0)
    {
      execl (g_kill_posix, "kill", "-f", "-s", "TERM", "-W", pid_arg,
             (char *) NULL);
      _exit (127);
    }

  int kstatus = 0;
  if (waitpid_timeout (kpid, &kstatus, 5000) != kpid
      || !WIFEXITED (kstatus) || WEXITSTATUS (kstatus) != 0)
    {
      fprintf (stderr, "kill-util: kill.exe failed with status 0x%x\n",
               (unsigned int) kstatus);
      goto out;
    }

  for (int i = 0; i < 3; i++)
    {
      DWORD win_ec = 99;
      if (WaitForSingleObject (handles[i], 2000) != WAIT_OBJECT_0
          || !GetExitCodeProcess (handles[i], &win_ec) || win_ec != 0)
        {
          fprintf (stderr,
                   "kill-util: node[%d] Win32 exit code = %lu (expected 0)\n",
                   i, (unsigned long) win_ec);
          goto out;
        }
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strcmp (marker, "TREE_ORDER_OK\n") != 0)
    {
      fprintf (stderr, "kill-util: unexpected marker '%s'\n", marker);
      goto out;
    }

  rc = 0;
out:
  if (pipe_rd)
    CloseHandle (pipe_rd);
  cleanup_case (-1, -1, handles, marker_posix);
  return rc;
}

/* 7. Mixed Win32 -> MSYS2 -> Win32 process tree:
 *    Verifies that native Win32 children spawned by an MSYS2 descendant
 *    (both via non-overlay _P_WAIT and via _P_OVERLAY exec) are not
 *    misclassified as MSYS2 processes via their PID_NOTCYGWIN winpid
 *    symlinks, and are properly terminated on SIGTERM. */
static int
test_mixed_win32_msys_win32_tree (const char *bridge_mode, const char *tag)
{
  char marker_posix[PATH_MAX], marker_win[PATH_MAX], line[128], marker[128];
  HANDLE handles[3] = { NULL, NULL, NULL };
  int rfd = -1, status = 0, rc = 1;
  unsigned long pids[3] = { 0, 0, 0 };

  if (make_marker_paths (tag, marker_posix, sizeof (marker_posix),
                         marker_win, sizeof (marker_win)) != 0)
    return 1;

  pid_t pid = spawn_captive_proctree_args ("mixed-tree", marker_win,
                                           g_self_win, bridge_mode, &rfd);
  if (pid < 0)
    return 1;

  if (read_line_timeout (rfd, line, sizeof (line), 5000) != 0
      || sscanf (line, "READY %lu %lu %lu",
                 &pids[0], &pids[1], &pids[2]) != 3)
    {
      fprintf (stderr, "%s: failed to read READY (got '%s')\n", tag, line);
      goto out;
    }

  if (open_win32_pids (tag, pids, handles, 3) != 0)
    goto out;

  if (kill (pid, SIGTERM) != 0)
    {
      perror ("kill(mixed-tree, SIGTERM)");
      goto out;
    }

  if (waitpid_timeout (pid, &status, 8000) != pid)
    {
      fprintf (stderr, "%s: waitpid timed out\n", tag);
      goto out;
    }
  pid = -1;

  if (!WIFSIGNALED (status) || WTERMSIG (status) != SIGTERM)
    {
      fprintf (stderr,
               "%s: unexpected waitpid status 0x%x (expected SIGTERM)\n",
               tag, (unsigned int) status);
      goto out;
    }

  /* Both the root Win32 node (handles[0]) and the leaf Win32 node (handles[2])
   * must be terminated with 128 + SIGTERM, and the intermediate MSYS2 node
   * (handles[1]) must also have exited. */
  for (int i = 0; i < 3; i++)
    {
      DWORD win_ec = 0;
      if (WaitForSingleObject (handles[i], 2000) != WAIT_OBJECT_0
          || !GetExitCodeProcess (handles[i], &win_ec))
        {
          fprintf (stderr, "%s: node[%d] (pid %lu) did not exit\n",
                   tag, i, pids[i]);
          goto out;
        }
      if ((i == 0 || i == 2) && win_ec != (DWORD) (128 + SIGTERM))
        {
          fprintf (stderr,
                   "%s: node[%d] exit code = %lu (expected %d)\n",
                   tag, i, (unsigned long) win_ec, 128 + SIGTERM);
          goto out;
        }
    }

  if (read_marker_file (marker_posix, marker, sizeof (marker)) <= 0
      || strstr (marker, "GOT_BREAK\n") == NULL)
    {
      fprintf (stderr, "%s: missing GOT_BREAK in marker '%s'\n", tag, marker);
      goto out;
    }

  rc = 0;
out:
  cleanup_case (pid, rfd, handles, marker_posix);
  return rc;
}

int
main (int argc, char **argv)
{
  if (argc == 4 && strcmp (argv[1], "--msys-bridge-spawn") == 0)
    {
      char helper_posix[PATH_MAX];
      if (cygwin_conv_path (CCP_WIN_A_TO_POSIX, argv[2],
                            helper_posix, sizeof (helper_posix)) != 0)
        return 2;
      spawnl (_P_WAIT, helper_posix, "win32-proctree", "stubborn-leaf",
              argv[3], (char *) NULL);
      return 0;
    }
  if (argc == 4 && strcmp (argv[1], "--msys-bridge-exec") == 0)
    {
      char helper_posix[PATH_MAX];
      if (cygwin_conv_path (CCP_WIN_A_TO_POSIX, argv[2],
                            helper_posix, sizeof (helper_posix)) != 0)
        return 2;
      execl (helper_posix, "win32-proctree", "stubborn-leaf",
             argv[3], (char *) NULL);
      return 2;
    }

  if (init_paths () != 0)
    return 1;

  if (test_mt_graceful_sigterm () != 0)
    return 1;
  if (test_tree_top_down_signal (SIGINT, "tree-sigint") != 0)
    return 1;
  if (test_tree_top_down_signal (SIGTERM, "tree-sigterm") != 0)
    return 1;
  if (test_repl_sigint_survival_and_sigquit () != 0)
    return 1;
  if (test_stubborn_tree_sigterm_fallback () != 0)
    return 1;
  if (test_stubborn_tree_sigkill () != 0)
    return 1;
  if (test_kill_util_force_winpid () != 0)
    return 1;
  if (test_mixed_win32_msys_win32_tree ("--msys-bridge-spawn",
                                        "mixed-spawn") != 0)
    return 1;
  if (test_mixed_win32_msys_win32_tree ("--msys-bridge-exec",
                                        "mixed-exec") != 0)
    return 1;

  return 0;
}
