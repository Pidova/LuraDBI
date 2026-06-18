/*
 Dism details are currently not getting set with dism iter (bug) this is to counter it
*/
#pragma once
#include <capstone/capstone.h>
#include <capstone/x86.h>

namespace luramas::fast_groups {

      inline constexpr bool is_call(const x86_insn i) {
            switch (i) {
                  case x86_insn::X86_INS_CALL:
                  case x86_insn::X86_INS_LCALL:
                  case x86_insn::X86_INS_SYSCALL:
                  case x86_insn::X86_INS_VMCALL:
                  case x86_insn::X86_INS_VMMCALL: {
                        return true;
                  }
                  default: {
                        return false;
                  }
            }
      }

      inline constexpr bool is_return(const x86_insn i) {
            switch (i) {
                  case x86_insn::X86_INS_IRET:
                  case x86_insn::X86_INS_IRETD:
                  case x86_insn::X86_INS_IRETQ:
                  case x86_insn::X86_INS_RETF:
                  case x86_insn::X86_INS_RETFQ:
                  case x86_insn::X86_INS_SYSRET:
                  case x86_insn::X86_INS_SYSRETQ:
                  case x86_insn::X86_INS_RET: {
                        return true;
                  }
                  default: {
                        return false;
                  }
            }
      }

      inline constexpr bool is_not_conditional_jmp(const x86_insn i) {
            switch (i) {
                  case x86_insn::X86_INS_JMP:
                  case x86_insn::X86_INS_LJMP: {
                        return true;
                  }
                  default: {
                        return false;
                  }
            }
      }

      inline constexpr bool is_jmp(const x86_insn i) {
            if (is_not_conditional_jmp(i)) {
                  return true;
            }
            switch (i) {
                  case x86_insn::X86_INS_JE:
                  case x86_insn::X86_INS_JNE:
                  case x86_insn::X86_INS_JA:
                  case x86_insn::X86_INS_JAE:
                  case x86_insn::X86_INS_JB:
                  case x86_insn::X86_INS_JBE:
                  case x86_insn::X86_INS_JG:
                  case x86_insn::X86_INS_JGE:
                  case x86_insn::X86_INS_JL:
                  case x86_insn::X86_INS_JLE:
                  case x86_insn::X86_INS_JNO:
                  case x86_insn::X86_INS_JNP:
                  case x86_insn::X86_INS_JNS:
                  case x86_insn::X86_INS_JO:
                  case x86_insn::X86_INS_JP:
                  case x86_insn::X86_INS_JS:
                  case x86_insn::X86_INS_JRCXZ:
                  case x86_insn::X86_INS_JECXZ:
                  case x86_insn::X86_INS_JCXZ:
                  case x86_insn::X86_INS_LOOP:
                  case x86_insn::X86_INS_LOOPE:
                  case x86_insn::X86_INS_LOOPNE: {
                        return true;
                  }
                  default: {
                        return false;
                  }
            }
      }

} // namespace luramas::fast_groups