/**
 * Executable wrapper to fake syscall results returning absolute time
 * information. Calls to SYS_gettimeofday, SYS_clock_gettime, and SYS_time are
 * intercepted.
 *
 * NOTE: will not work for all calls on kernels (e.g. some x86_64) implementing
 * vsyscalls.
 **/

#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#if defined __i386__

    #define SYSCALL_NUM ORIG_EAX
    #define SYSCALL_RET EAX
    #define SYSCALL_ARG1 ebx
    #define SYSCALL_ARG2 ecx

#elif defined __x86_64__

    /*

    From http://en.wikipedia.org/wiki/X86_calling_conventions#AMD64_ABI_convention:

    The calling convention of the AMD64 application binary interface is
    followed on Linux and other non-Microsoft operating systems. The registers
    RDI, RSI, RDX, RCX, R8 and R9 are used for integer and pointer arguments
    while XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6 and XMM7 are used for
    floating point arguments. As in the Microsoft x64 calling convention,
    additional arguments are pushed onto the stack and the return value is
    stored in RAX.

    From http://www.x86-64.org/documentation/abi.pdf:

    A.2.1 Calling Conventions The Linux AMD64 kernel uses internally the same
    calling conventions as userlevel applications (see section 3.2.3 for
    details). User-level applications that like to call system calls should use
    the functions from the C library. The interface between the C library and
    the Linux kernel is the same as for the user-level applications with the
    following differences:

    1. User-level applications use as integer registers for passing the
    sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses
    %rdi, %rsi, %rdx, %r10, %r8 and %r9.

    2. A system-call is done via the syscall instruction. The kernel destroys
    registers %rcx and %r11.

    3. The number of the syscall has to be passed in register %rax.

    4. System-calls are limited to six arguments, no argument is passed
    directly on the stack.

    5. Returning from the syscall, register %rax contains the result of the
    system-call. A value in the range between -4095 and -1 indicates an error,
    it is -errno.

    6. Only values of class INTEGER or class MEMORY are passed to the kernel.

    */

    #define SYSCALL_NUM ORIG_RAX
    #define SYSCALL_RET RAX
    #define SYSCALL_ARG1 rdi
    #define SYSCALL_ARG2 rsi

#endif

/*
#define DEBUG
*/

int
main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s offset executable\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* calculate timespec arguments */
    double offset = atof(argv[1]);
    time_t sec_offset = rint(offset);
    long nsec_offset = 1000000000 * (offset - sec_offset);
    suseconds_t usec_offset = 1000000 * (offset - sec_offset);

    #ifdef DEBUG
    fprintf(stderr, "Offsetting gettimeofday and clock_gettime syscalls by %lds+%ldns\n", sec_offset, nsec_offset);
    #endif

    char* executable = argv[2];

    pid_t pid = fork();
    switch (pid) {
    case -1:
        /* failed */
        perror("couldn't fork");
        return EXIT_FAILURE;
    case 0:
        /* child */
        if (ptrace(PTRACE_TRACEME, 0, (char*) 1, 0) < 0) {
            perror("ptrace(PTRACE_TRACEME, ...)");
            return EXIT_FAILURE;
        }
        kill(getpid(), SIGSTOP);
        execv(executable, &argv[3]);
        perror(executable);
        _exit(1);
        break;
    default:
      {
        /* parent */

        int insyscall = 0;
        long syscallno;
        #ifdef DEBUG
        long retval;
        #endif
        time_t sec = 0;
        long nsec = 0;
        suseconds_t usec;
        struct user_regs_struct regs;
        int status;
        for (;;) {
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) /* process exit */
                break;

            syscallno = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_NUM, 0);

            switch (syscallno) {
              case SYS_gettimeofday:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: gettimeofday(tv=%ld,tz=%ld)\n", regs.SYSCALL_ARG1, regs.SYSCALL_ARG2);
                    #endif
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* struct timeval* tv parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1, 0);
                    usec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1 + sizeof(time_t), 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "tt: gettimeofday(tv->tv_sec=%ld,tv->tv_usec=%ld)=%ld --> *tv={%ld,%ld}\n", sec, usec, retval, sec + sec_offset, usec + usec_offset);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec += sec_offset;
                    usec += usec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), usec);
                }
                break;
              case SYS_clock_gettime:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: clock_gettime(clockid=%ld,tp=0x%x)\n", regs.SYSCALL_ARG1, (unsigned int) regs.SYSCALL_ARG2);
                    #endif
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* struct timespec* tp parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2, 0);
                    nsec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "tt: clock_gettime(tp->tv_sec=%ld,tp->tv_nsec=%ld)=%ld --> *tp={%ld,%ld}\n", sec, nsec, retval, sec + sec_offset, nsec + nsec_offset);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec += sec_offset;
                    nsec += nsec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), nsec);
                }
                break;
              case SYS_time:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: time(t=0x%x)\n", (unsigned int) regs.SYSCALL_ARG1);
                    #endif
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* time_t* t parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1, 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "tt: time(*t=%ld)=%ld --> *t=%ld\n", sec, retval, sec + sec_offset);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec += sec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
                }
                break;
            }

            if (ptrace(PTRACE_SYSCALL, pid, (char*) 1, 0) < 0) {
                perror("resume: ptrace(PTRACE_SYSCALL, ...)");
                return EXIT_FAILURE;
            }
        }
        ptrace(PTRACE_DETACH, pid, (char*) 1, 0);
        break;
      }
    }
    return EXIT_SUCCESS;
}
