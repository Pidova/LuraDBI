
/*


MSDOS:
    qemu-img create -f raw msdos.img 20M
    qemu-system-x86_64.exe  -plugin ":\projects\LuraDBI\x64\Release\QEMU.dll" -drive file="C:\qemudumps\MS-DOS.iso",format=raw,media=cdrom -drive file=msdos.img,format=raw,media=disk

Windows 10:
    cd /d C:\qemu_imgs
    qemu-img create -f qcow2 win10.qcow2 80G
    qemu-system-x86_64.exe -m 16G -boot d -cdrom "C:\vm\windows\windows.iso" -drive file="win10.qcow2",format=qcow2 -vga qxl -smp 16 -plugin "C:\projects\LuraDBI\x64\Release\QEMU.dll"

To invoke quit:
    CTRL + ALT + 2
    stop
    quit

*/
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../config.hpp"
#include "../shared/fast_groups.hpp"
#include "../shared/luramas/basic_info.hpp"
#include "../shared/luramas/blocks.hpp"
#include "../shared/x86_regs.hpp"
#include <algorithm>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/smart_ptr.hpp>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <cstdint>
#include <mutex>
#include <qemu/qemu-plugin.h>
#include <shared_mutex>
#include <windows.h>
#include <winsock2.h>

namespace lurapro {

      using range = std::pair<luramas::profile::address, luramas::profile::address>; /* [start, end] */

      template <typename T>
      using vcpu_vec = boost::container::vector<T>;

      using block = luramas::blocks::block<config::MAX_LEN>;
      using inst = luramas::blocks::inst_data<config::MAX_LEN>;
      using edge = luramas::blocks::edges::jmp_loc;
      using edge_hash = luramas::blocks::edges::jmp_loc_hash;

      /* Data */
      HMODULE mod;
      std::shared_mutex *tbmutex = nullptr;

      /* VCPU ID reqs */
      vcpu_vec<luramas::profile::address> *curr_pc = nullptr;                               /* Curr reak PC with VCPU IDX */
      vcpu_vec<luramas::profile::address> *real_pc = nullptr;                               /* Real PC with VCPU IDX */
      vcpu_vec<boost::fixed_vector<edge, config::MAX_BUFFER_EDGES>> *prevd_jumps = nullptr; /* Given next instruction if prev inst is set and diff logs it here */
      vcpu_vec<boost::unordered_flat_set<edge, edge_hash>> *prevd_jumps_set = nullptr;      /* Jmp locs */

      namespace capstone_handles {

            struct handle {
                  csh ch;
                  cs_insn *insn;
                  luramas::blocks::interpretation_mode imode = luramas::blocks::interpretation_mode::none;
            };
            thread_local boost::container::vector<handle> handles;
      } // namespace capstone_handles

      namespace save {

            std::ofstream *save = nullptr;                    /* Saves inst data */
            vcpu_vec<std::ofstream> *save_jmp_locs = nullptr; /* Save jmp loc data */
      } // namespace save

      namespace translation {

            boost::icl::interval_set<luramas::profile::address> *logged_ranges = nullptr;
            vcpu_vec<boost::shared_ptr<block>> *block_graveyard = nullptr;
            boost::unordered_flat_map<luramas::profile::address, boost::shared_ptr<block>> *blocks = nullptr;

      } // namespace translation

      inline void init() {

            if (!lurapro::tbmutex) {
                  lurapro::tbmutex = new std::shared_mutex();
            }
            if (!lurapro::curr_pc) {
                  lurapro::curr_pc = new vcpu_vec<luramas::profile::address>();
            }
            if (!lurapro::real_pc) {
                  lurapro::real_pc = new vcpu_vec<luramas::profile::address>();
            }
            if (!lurapro::prevd_jumps) {
                  lurapro::prevd_jumps = new vcpu_vec<boost::fixed_vector<edge, config::MAX_BUFFER_EDGES>>();
            }
            if (!lurapro::prevd_jumps_set) {
                  lurapro::prevd_jumps_set = new vcpu_vec<boost::unordered_flat_set<edge, edge_hash>>();
            }
            if (!translation::logged_ranges) {
                  translation::logged_ranges = new boost::icl::interval_set<luramas::profile::address>();
            }
            if (!translation::blocks) {
                  translation::blocks = new boost::unordered_flat_map<luramas::profile::address, boost::shared_ptr<block>>();
            }
            if (!translation::block_graveyard) {
                  translation::block_graveyard = new vcpu_vec<boost::shared_ptr<block>>();
            }
            if (!save::save) {
                  save::save = new std::ofstream(std::string(config::directory) + config::mainsave_name + config::extension, std::ios::binary);
            }
            if (!save::save_jmp_locs) {
                  save::save_jmp_locs = new vcpu_vec<std::ofstream>();
            }
            return;
      }
      inline void destroy() {

            if (save::save) {
                  if (save::save->is_open()) {
                        save::save->flush();
                        save::save->close();
                  }
                  delete save::save;
                  save::save = nullptr;
            }
            if (save::save_jmp_locs) {
                  for (auto &o : *save::save_jmp_locs) {
                        if (o.is_open()) {
                              o.flush();
                              o.close();
                        }
                  }
                  delete save::save_jmp_locs;
                  save::save_jmp_locs = nullptr;
            }
            if (translation::blocks) {
                  translation::blocks->clear();
                  delete translation::blocks;
                  translation::blocks = nullptr;
            }
            if (translation::logged_ranges) {
                  translation::logged_ranges->clear();
                  delete translation::logged_ranges;
                  translation::logged_ranges = nullptr;
            }
            if (prevd_jumps_set) {
                  prevd_jumps_set->clear();
                  delete prevd_jumps_set;
                  prevd_jumps_set = nullptr;
            }
            if (lurapro::prevd_jumps) {
                  prevd_jumps->clear();
                  delete prevd_jumps;
                  prevd_jumps = nullptr;
            }
            if (translation::block_graveyard) {
                  translation::block_graveyard->clear();
                  delete translation::block_graveyard;
                  translation::block_graveyard = nullptr;
            }
            if (lurapro::real_pc) {
                  delete lurapro::real_pc;
                  lurapro::real_pc = nullptr;
            }
            if (lurapro::tbmutex) {
                  delete lurapro::tbmutex;
                  lurapro::tbmutex = nullptr;
            }
            return;
      }
} // namespace lurapro

inline std::size_t disassemble(const lurapro::capstone_handles::handle &handle, const lurapro::inst &inst, char *buffer, const std::size_t buffer_size) {

      if (inst.inst.bytes.empty()) {
            return 0u;
      }

      const auto *tmp_ptr = inst.inst.bytes.data();
      std::size_t ts = inst.inst.bytes.size();
      std::uint64_t ta = inst.inst.pc;
      csh capstone_handle = handle.ch;
      cs_insn *insn = handle.insn;
      if (cs_disasm_iter(capstone_handle, &tmp_ptr, &ts, &ta, insn)) {
            return std::snprintf(buffer, buffer_size, "%s %s", insn->mnemonic, insn->op_str);
      }
      return 0u;
}

inline luramas::profile::address get_real_address(const std::uint32_t vcpu_index) {

      auto &v = *lurapro::real_pc;
      auto &cnt = v[vcpu_index];
      const auto result = (cnt * v.size()) + vcpu_index;
      ++cnt;
      return result;
}

inline luramas::blocks::interpretation_mode get_mode(const char *const dism, const lurapro::inst &inst) {

      char buffer[512u];
      const auto dism_len = std::strlen(dism);
      for (const auto &h : lurapro::capstone_handles::handles) {

            if (const auto &n = disassemble(h, inst, buffer, sizeof(buffer)); n && n == dism_len && !std::memcmp(buffer, dism, dism_len)) {

                  return h.imode;
            }
      }
      return config::default_mode;
}
/* On Inst execute validate it or no */
static void first_inst_exec_cb(unsigned vcpu_index, void *userdata) {

      /* Once it excutes mark the inst as valid */
      const auto inst = reinterpret_cast<lurapro::inst *>(userdata);
      const auto valid = inst->valid.exchange(true);
      auto &prev = (*lurapro::curr_pc)[vcpu_index];
      if (!valid) {
            inst->inst.vcpu = vcpu_index;
            inst->inst.real_pc = get_real_address(vcpu_index);
      } else if (prev != inst->inst.prev_real_pc) {
            /* Previous instruction came from somewhere else */
            lurapro::prevd_jumps->at(vcpu_index).emplace_back(lurapro::edge(inst->inst.real_pc, prev));
      }
      inst->inst.prev_real_pc = prev;
      prev = inst->inst.real_pc;
      return;
}
static void inst_exec_cb(unsigned vcpu_index, void *userdata) {

      /* Once it excutes mark the inst as valid */
      const auto inst = reinterpret_cast<lurapro::inst *>(userdata);
      const auto valid = inst->valid.exchange(true);
      auto &prev = (*lurapro::curr_pc)[vcpu_index];
      if (!valid) {
            inst->inst.vcpu = vcpu_index;
            inst->inst.real_pc = get_real_address(vcpu_index);
      }
      inst->inst.prev_real_pc = prev;
      prev = inst->inst.real_pc;
      return;
}

/* Translation block execution CB */
static void tb_exec_cb(unsigned vcpu_index, void *userdata) {

      auto &djmps = lurapro::prevd_jumps->at(vcpu_index);
      auto &jset = lurapro::prevd_jumps_set->at(vcpu_index);
      jset.insert(djmps.begin(), djmps.end());
      djmps.clear();
      if (jset.size() > config::MAX_BUFFER_EDGES_SET) {
            luramas::blocks::edges::save(jset, lurapro::save::save_jmp_locs->at(vcpu_index));
            jset.clear();
      }
      return;
}

/* Translate per block CB */
static void __cdecl tb_trans_cb(qemu_plugin_id_t id, qemu_plugin_tb *tb) {

      const auto instc = qemu_plugin_tb_n_insns(lurapro::mod)(tb);
      if (!instc) {
            return;
      }
      auto b = boost::make_shared<lurapro::block>();
      b->time = std::time(nullptr);
      b->inst_count = instc;
      b->vcpu_n = (*lurapro::real_pc).size();

      /* Translate current block */
      {
            bool fhas_pc = false;
            b->insts.reserve(instc);
            for (auto i = 0u; i < instc; ++i) {

                  const auto insn = qemu_plugin_tb_get_insn(lurapro::mod)(tb, i);
                  const auto len = qemu_plugin_insn_size(lurapro::mod)(insn);
                  if (!len) {
                        continue;
                  }

                  /* Set PC */
                  const auto pc = static_cast<luramas::profile::address>(qemu_plugin_insn_vaddr(lurapro::mod)(insn));
                  if (!fhas_pc) {
                        fhas_pc = true;
                        b->loc = pc;
                  }
                  b->insts.emplace_back();
                  auto &inst = b->insts.back();

                  /* Write bytes to TB */
                  inst.inst.bytes.resize(len);
                  qemu_plugin_insn_data(lurapro::mod)(insn, inst.inst.bytes.data(), len);

                  /* Inst incomplete data */
                  inst.inst.pc = pc;
                  qemu_plugin_register_vcpu_insn_exec_cb(lurapro::mod)(insn, !i ? first_inst_exec_cb : inst_exec_cb, QEMU_PLUGIN_CB_R_REGS, reinterpret_cast<void *>(&b->insts[i]));

                  /* Get mode */
                  if (!i) {
                        b->interpretation_id = get_mode(qemu_plugin_insn_disas(lurapro::mod)(insn), inst);
                  }
            }
            if (!fhas_pc) {
                  return;
            }
      }
      if (b->insts.empty()) {
            return;
      }
      const auto range = lurapro::range(b->loc, (b->insts.back().inst.pc + b->insts.back().inst.bytes.size() - 1u));

      /* See if current block is getting translated again */
      {
            qemu_plugin_register_vcpu_tb_exec_cb(lurapro::mod)(tb, tb_exec_cb, QEMU_PLUGIN_CB_R_REGS, NULL);

            std::unique_lock<std::shared_mutex> lock(*lurapro::tbmutex);
            if (lurapro::translation::block_graveyard->size() >= lurapro::translation::block_graveyard->capacity()) {
                  lurapro::translation::block_graveyard->reserve(!lurapro::translation::block_graveyard->capacity() ? 1024u : lurapro::translation::block_graveyard->capacity() * 2);
            }
            auto bit = lurapro::translation::blocks->find(range.first);
            if (bit != lurapro::translation::blocks->end()) {

                  bit->second->fretranslated = true;
                  auto it = lurapro::translation::logged_ranges->find(boost::icl::discrete_interval<luramas::profile::address>::closed(range.first, range.first));
                  if (it != lurapro::translation::logged_ranges->end()) {
                        lurapro::translation::logged_ranges->erase(it);
                  }

                  lurapro::translation::block_graveyard->emplace_back(bit->second);
                  lurapro::translation::blocks->erase(bit);
            }

            bit = lurapro::translation::blocks->find(range.second);
            if (bit != lurapro::translation::blocks->end()) {

                  bit->second->fretranslated = true;
                  auto it = lurapro::translation::logged_ranges->find(boost::icl::discrete_interval<luramas::profile::address>::closed(range.second, range.second));
                  if (it != lurapro::translation::logged_ranges->end()) {
                        lurapro::translation::logged_ranges->erase(it);
                  }

                  lurapro::translation::block_graveyard->emplace_back(bit->second);
                  lurapro::translation::blocks->erase(bit);
            }
            /* Log block */
            lurapro::translation::logged_ranges->insert(boost::icl::discrete_interval<luramas::profile::address>::closed(range.first, range.second));
            lurapro::translation::blocks->insert_or_assign(range.first, std::move(b));
      }
      return;
}

static void __cdecl vcpu_init_cb(qemu_plugin_id_t id, std::uint32_t vcpu_index) {

      std::unique_lock<std::shared_mutex> lock(*lurapro::tbmutex);
      if (lurapro::real_pc->size() <= vcpu_index) {
            lurapro::real_pc->resize(vcpu_index + 1u);
      }
      if (lurapro::curr_pc->size() <= vcpu_index) {
            lurapro::curr_pc->resize(vcpu_index + 1u);
      }
      if (lurapro::prevd_jumps->size() <= vcpu_index) {
            lurapro::prevd_jumps->resize(vcpu_index + 1u);
      }
      if (lurapro::prevd_jumps_set->size() <= vcpu_index) {
            lurapro::prevd_jumps_set->resize(vcpu_index + 1u);
            lurapro::prevd_jumps_set->at(vcpu_index).reserve(config::MAX_BUFFER_EDGES_SET);
      }
      if (lurapro::save::save_jmp_locs->size() <= vcpu_index) {
            lurapro::save::save_jmp_locs->resize(vcpu_index + 1u);
            lurapro::save::save_jmp_locs->at(vcpu_index) = std::ofstream(std::string(config::directory) + config::savelocs_name + std::to_string(vcpu_index) + config::extension, std::ios::binary);
      }
      switch (config::arch) {
            case luramas::blocks::arch::x86: {
                  if (csh h; cs_open(CS_ARCH_X86, CS_MODE_16, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::x16));
                  }
                  if (csh h; cs_open(CS_ARCH_X86, CS_MODE_32, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::x32));
                  }
                  if (csh h; cs_open(CS_ARCH_X86, CS_MODE_64, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::x64));
                  }
                  break;
            }
            case luramas::blocks::arch::ARM: {
                  if (csh h; cs_open(CS_ARCH_ARM, CS_MODE_ARM, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::arm32));
                  }
                  if (csh h; cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::arm_thumb));
                  }
                  if (csh h; cs_open(CS_ARCH_ARM, CS_MODE_MCLASS, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::arm_mclass));
                  }
                  if (csh h; cs_open(CS_ARCH_ARM, CS_MODE_V8, &h) == CS_ERR_OK) {
                        cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON);
                        lurapro::capstone_handles::handles.emplace_back(lurapro::capstone_handles::handle(h, cs_malloc(h), luramas::blocks::interpretation_mode::arm_v8));
                  }
                  break;
            }
            default: {
                  break;
            }
      }
      return;
}

/* On vcpu exit CB save instruction data */
static void __cdecl at_exit_cb(qemu_plugin_id_t id, void *userdata) {

      for (const auto &[_, b] : *lurapro::translation::blocks) {
            b->write(*lurapro::save::save);
      }
      for (const auto &i : *lurapro::translation::block_graveyard) {
            i->write(*lurapro::save::save);
      }
      for (auto idx = 0u; idx < lurapro::prevd_jumps_set->size(); ++idx) {
            luramas::blocks::edges::save(lurapro::prevd_jumps_set->at(idx), lurapro::save::save_jmp_locs->at(idx));
      }
      lurapro::destroy();
      return;
}

/* Flushes graveyard */
static void __cdecl vcpu_tb_flush_cb(qemu_plugin_id_t id) {

      std::unique_lock<std::shared_mutex> lock(*lurapro::tbmutex);
      if (lurapro::translation::block_graveyard) {
            for (const auto &i : *lurapro::translation::block_graveyard) {
                  i->write(*lurapro::save::save);
            }
            lurapro::translation::block_graveyard->clear();
      }
      return;
}

extern "C" QEMU_PLUGIN_EXPORT int __cdecl qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {

      lurapro::init();
      lurapro::mod = LoadLibraryA("qemu-system-x86_64.exe");
      qemu_plugin_register_vcpu_tb_trans_cb(lurapro::mod)(id, tb_trans_cb);
      qemu_plugin_register_vcpu_init_cb(lurapro::mod)(id, vcpu_init_cb);
      qemu_plugin_register_atexit_cb(lurapro::mod)(id, at_exit_cb, NULL);
      qemu_plugin_register_flush_cb(lurapro::mod)(id, vcpu_tb_flush_cb);
      return 0;
}