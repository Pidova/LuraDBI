
/*


MSDOS:
    qemu-img create -f raw msdos.img 20M
    qemu-system-x86_64.exe  -plugin ":\projects\LuraDBI\x64\Release\QEMU.dll" -drive file="C:\qemudumps\MS-DOS.iso",format=raw,media=cdrom -drive file=msdos.img,format=raw,media=disk

Windows 10:
    cd /d C:\qemu_imgs
    qemu-img create -f qcow2 win10.qcow2 80G
    qemu-system-x86_64.exe ^
  -m 16G ^
  -smp 16 ^
  -accel tcg,thread=multi,tb-size=4096 ^
  -boot d ^
  -cdrom "C:\vm\windows\windows.iso" ^
  -drive file="C:\vm\windows\virtio-win.iso",media=cdrom,id=virtio_drivers ^
  -drive file=win10.qcow2,if=none,id=hd0,format=qcow2,cache=unsafe,aio=threads ^
  -device ide-hd,drive=hd0 ^
  -vga none ^
  -device virtio-vga ^
  -plugin "C:\projects\LuraDBI\x64\Release\QEMU.dll"
To invoke quit:
    CTRL + ALT + 2
    stop
    quit

*/
// Standard Library
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
//#define QEMU_PLUGIN_DELAY_CBS 1
//#define QEMU_DUMP_REG_LIST 1

/* Profile globals and defintions */
namespace lurapro {

      using range = std::pair<luramas::profile::address, luramas::profile::address>; /* [start, end] */
      using block = luramas::blocks::block<config::MAX_LEN>;                         /* Internal translation block */
      using inst = luramas::blocks::inst_data<config::MAX_LEN>;                      /* Instruction with max allowed instruction width */
      using edge = luramas::blocks::edges::jmp_loc;                                  /* Each edge to a translation block */
      using edge_hash = luramas::blocks::edges::jmp_loc_hash;                        /* Edge hashing */

      template <typename T>
      using vcpu_vec = boost::container::vector<T>; /* Each VCPU gets there own vector to prevent race conditions, thread_local can not be used as when on exit one thread is only used so it is unsafe */

      /* Data */
#ifdef _WIN32
      HMODULE mod; /* Module for Windows support */
#endif
      std::shared_mutex *tbmutex = nullptr; /* When a block gets translated or saved this is active. */

      /* VCPU ID reqs */
      vcpu_vec<std::optional<luramas::profile::address>> *curr_pc = nullptr;            /* Curr real PC with VCPU IDX */
      vcpu_vec<luramas::profile::address> *real_pc = nullptr;                           /* Real PC with VCPU IDX */
      vcpu_vec<boost::fixed_vector<edge, config::MAX_BUFFER_N>> *prevd_jumps = nullptr; /* Given next instruction if prev inst is set and diff logs it here */
      vcpu_vec<boost::unordered_flat_set<edge, edge_hash>> *prevd_jumps_set = nullptr;  /* Jmp locs */
#ifdef QEMU_PLUGIN_DELAY_CBS
      std::atomic<bool> start_cbs{false}; /* Start CBs at a later time */
#endif

      namespace capstone_handles {

            struct handle {
                  csh ch;                                                                                  /* Capstone handle */
                  cs_insn *insn;                                                                           /* Output instruction array */
                  luramas::blocks::interpretation_mode imode = luramas::blocks::interpretation_mode::none; /* Architecture interpretation mode */
            };
            thread_local boost::container::vector<handle> handles;
      } // namespace capstone_handles

      namespace save {

            std::ofstream *save = nullptr;                    /* Saves inst data */
            vcpu_vec<std::ofstream> *save_jmp_locs = nullptr; /* Save jmp loc data */
            boost::asio::thread_pool *pool = nullptr;         /* Thread pool for background saves */
      } // namespace save

      namespace translation {

            boost::icl::interval_set<luramas::profile::address> *logged_ranges = nullptr;                     /* Ranged of each block to track SMCs */
            vcpu_vec<boost::shared_ptr<block>> *block_graveyard = nullptr;                                    /* Appended blocks so they only get destroyed once tbs get flushed */
            boost::unordered_flat_map<luramas::profile::address, boost::shared_ptr<block>> *blocks = nullptr; /* Block pointers */
            std::size_t global_block_id = 0u;                                                                 /* Global block ID relative to other IDs */
      } // namespace translation

      namespace vcpu {

            vcpu_vec<boost::container::vector<luramas::blocks::vcpu::captured_block_state>> *vcpu_states = nullptr; /* VCPU states */
      } // namespace vcpu

      namespace interrupts {

            vcpu_vec<boost::container::vector<luramas::blocks::interrupts::interrupt>> *ints = nullptr; /* Interrupts */
      }

      namespace mmio {

            struct mmio_data {
                  std::ofstream file;                                                                    /* Buffer file */
                  boost::unordered_flat_set<luramas::blocks::mmio::data, luramas::blocks::mmio::hash> d; /* Data */
            };
            vcpu_vec<mmio_data> *data = nullptr; /* Save data */
      } // namespace mmio

      /* Qemu function wrapper allow support for other OS's */
      template <auto Func>
      struct qemu_w_t {
            template <typename... Args>
            inline auto operator()(Args &&...args) const {
#ifdef _WIN32
                  return Func(lurapro::mod)(std::forward<Args>(args)...);
#else
                  return Func(std::forward<Args>(args)...);
#endif
            }
      };

      /* QEMU Wrapper */
      template <auto Func>
      inline constexpr qemu_w_t<Func> qemu_w{};

      /* Init/Destroy all global pointers */
      inline void init() {

            {
                  if (!lurapro::tbmutex) {
                        lurapro::tbmutex = new std::shared_mutex();
                  }
                  if (!lurapro::curr_pc) {
                        lurapro::curr_pc = new vcpu_vec<std::optional<luramas::profile::address>>();
                  }
                  if (!lurapro::real_pc) {
                        lurapro::real_pc = new vcpu_vec<luramas::profile::address>();
                  }
                  if (!lurapro::prevd_jumps) {
                        lurapro::prevd_jumps = new vcpu_vec<boost::fixed_vector<edge, config::MAX_BUFFER_N>>();
                  }
                  if (!lurapro::prevd_jumps_set) {
                        lurapro::prevd_jumps_set = new vcpu_vec<boost::unordered_flat_set<edge, edge_hash>>();
                  }
            }
            {
                  if (!vcpu::vcpu_states) {
                        vcpu::vcpu_states = new vcpu_vec<boost::container::vector<luramas::blocks::vcpu::captured_block_state>>();
                  }
                  if (!interrupts::ints) {
                        interrupts::ints = new vcpu_vec<boost::container::vector<luramas::blocks::interrupts::interrupt>>();
                  }
            }
            {
                  if (!translation::logged_ranges) {
                        translation::logged_ranges = new boost::icl::interval_set<luramas::profile::address>();
                  }
                  if (!translation::blocks) {
                        translation::blocks = new boost::unordered_flat_map<luramas::profile::address, boost::shared_ptr<block>>();
                  }
                  if (!translation::block_graveyard) {
                        translation::block_graveyard = new vcpu_vec<boost::shared_ptr<block>>();
                  }
            }
            {
                  if (!save::save) {
                        save::save = new std::ofstream(std::string(config::directory) + config::mainsave_name + config::extension, std::ios::binary);
                  }
                  if (!save::save_jmp_locs) {
                        save::save_jmp_locs = new vcpu_vec<std::ofstream>();
                  }
                  if (!save::pool) {
                        save::pool = new boost::asio::thread_pool(1u);
                  }
            }
            {
                  if (!mmio::data) {
                        mmio::data = new vcpu_vec<mmio::mmio_data>();
                  }
            }
            return;
      }
      inline void destroy() {

            {
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
                  if (save::pool) {
                        save::pool->join();
                        delete save::pool;
                        save::pool = nullptr;
                  }
            }
            {
                  if (vcpu::vcpu_states) {
                        vcpu::vcpu_states->clear();
                        delete vcpu::vcpu_states;
                        vcpu::vcpu_states = nullptr;
                  }
            }
            {
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
                  if (translation::block_graveyard) {
                        translation::block_graveyard->clear();
                        delete translation::block_graveyard;
                        translation::block_graveyard = nullptr;
                  }
            }
            {
                  if (interrupts::ints) {
                        interrupts::ints->clear();
                        delete interrupts::ints;
                        interrupts::ints = nullptr;
                  }
            }
            {
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
                  if (lurapro::real_pc) {
                        delete lurapro::real_pc;
                        lurapro::real_pc = nullptr;
                  }
                  if (lurapro::tbmutex) {
                        delete lurapro::tbmutex;
                        lurapro::tbmutex = nullptr;
                  }
            }
            {
                  if (!mmio::data) {
                        mmio::data->clear();
                        delete mmio::data;
                        mmio::data = nullptr;
                  }
            }
            return;
      }
} // namespace lurapro

namespace helpers {

      /* Compare buffer string with capstones disassembly string output. */
      inline std::size_t disassemble(const lurapro::capstone_handles::handle &handle, const lurapro::inst &inst, char *buffer, const std::size_t buffer_size) {

            if (inst.inst.bytes.empty()) {
                  return 0u;
            }
            const auto *tmp_ptr = inst.inst.bytes.data();
            std::size_t ts = inst.inst.bytes.size();
            std::uint64_t ta = inst.inst.pc;
            auto insn = handle.insn;
            return cs_disasm_iter(handle.ch, &tmp_ptr, &ts, &ta, insn) ? std::snprintf(buffer, buffer_size, "%s %s", insn->mnemonic, insn->op_str) : 0u;
      }

      /* Gets real address, logical PC tracked relative to incoming VCPU */
      inline luramas::profile::address get_real_address(const std::uint32_t vcpu_index) {

            auto &v = *lurapro::real_pc;
            auto &cnt = v[vcpu_index];
            const auto result = (cnt * v.size()) + vcpu_index;
            ++cnt;
            return result;
      }

      /* Gets interpration mode through QEMUs disassembly output (Internal mode is not exposed without modifying QEMU) */
      inline std::pair<luramas::blocks::interpretation_mode, lurapro::capstone_handles::handle> get_mode(const char *const dism, const lurapro::inst &inst) {

            char buffer[512u];
            const auto dism_len = std::strlen(dism);
            for (const auto &h : lurapro::capstone_handles::handles) {

                  if (const auto &n = disassemble(h, inst, buffer, sizeof(buffer)); n && n == dism_len && !std::memcmp(buffer, dism, dism_len)) {

                        return std::make_pair(h.imode, h);
                  }
            }
            return std::make_pair(config::default_mode, lurapro::capstone_handles::handles.front());
      }

      /* Gets capstone OP ID */
      inline std::optional<std::uint32_t> get_op_id(const lurapro::capstone_handles::handle &handle, const lurapro::inst &inst) {

            const auto *tmp_ptr = inst.inst.bytes.data();
            std::size_t ts = inst.inst.bytes.size();
            std::uint64_t ta = inst.inst.pc;
            auto insn = handle.insn;
            return cs_disasm_iter(handle.ch, &tmp_ptr, &ts, &ta, insn) ? std::optional<std::uint32_t>(insn->id) : std::nullopt;
      }

      /* Reads register returns true if successful */
      inline bool read_register(GByteArray *buffer, const std::size_t idx, const GArray *arr) {

            const auto &desc = reinterpret_cast<qemu_plugin_reg_descriptor *>(arr->data)[idx];
            g_byte_array_set_size(buffer, 0u);
            return lurapro::qemu_w<qemu_plugin_read_register>(desc.handle, buffer) != -1 && buffer->len;
      }
} // namespace helpers

namespace process {

      namespace inst {

            /* Process first instruction */
            __forceinline void first(const std::uint32_t vcpu_index, lurapro::inst &inst) {

                  /* Once it excutes mark the inst as valid */
                  auto &prev = (*lurapro::curr_pc)[vcpu_index];
                  if (!inst.fvalid) [[unlikely]] {
                        inst.fvalid = true;
                        inst.inst.vcpu = vcpu_index;
                        inst.inst.real_pc = helpers::get_real_address(vcpu_index);
                  } else if (!prev || (inst.inst.fvalid_prev_real_pc && *prev != inst.inst.prev_real_pc)) [[unlikely]] {
                        /* Previous instruction came from somewhere else */
                        (*lurapro::prevd_jumps)[vcpu_index].emplace_back(lurapro::edge(prev != std::nullopt, inst.inst.real_pc, prev.value_or(0u)));
                  }
                  if (!inst.inst.fvalid_prev_real_pc && prev) [[unlikely]] {
                        inst.inst.prev_real_pc = *prev;
                        inst.inst.fvalid_prev_real_pc = true;
                  }
                  prev = inst.inst.real_pc;
                  return;
            }

            /* Process an instruction */
            __forceinline void inst(const std::uint32_t vcpu_index, lurapro::inst *inst) {

                  /* Once it excutes mark the inst as valid */
                  auto &prev = (*lurapro::curr_pc)[vcpu_index];
                  if (!inst->fvalid) [[unlikely]] {
                        inst->fvalid = true;
                        inst->inst.vcpu = vcpu_index;
                        inst->inst.real_pc = helpers::get_real_address(vcpu_index);
                  }
                  inst->inst.prev_real_pc = *prev;
                  prev = inst->inst.real_pc;
                  return;
            }
      } // namespace inst
} // namespace process

namespace cbs {

      namespace inst {

            namespace debug {

                  /* Print regs */
                  static void __cdecl print_regs(std::uint32_t vcpu_index, void *userdata) {

                        const auto arr = lurapro::qemu_w<qemu_plugin_get_registers>();
                        if (!arr || !arr->data) {
                              return;
                        }
                        thread_local GByteArray *buf = g_byte_array_new();
                        for (auto i = 0u; i < arr->len; ++i) {

                              if (!helpers::read_register(buf, i, arr)) {
                                    continue;
                              }
#ifdef QEMU_DUMP_REG_LIST
                              std::printf("%s = %d,", reinterpret_cast<qemu_plugin_reg_descriptor *>(arr->data)[i].name, i);
#else
                              std::printf("[%d]%-8s | Size: %d bytes | Value: 0x", i, reinterpret_cast<qemu_plugin_reg_descriptor *>(arr->data)[i].name, buf->len);
                              for (auto j = 0u; j < buf->len; ++j) {
                                    std::printf("%02X", buf->data[j]);
                              }
#endif
                              std::printf("\n");
                        }
                        return;
                  }
            } // namespace debug

            namespace arch {

                  namespace x86 {

                        /* CB for memstorage for detecting MMIO */
                        static void __cdecl mem_write(std::uint32_t vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *userdata) {

                              if (lurapro::qemu_w<qemu_plugin_hwaddr_is_io>(lurapro::qemu_w<qemu_plugin_get_hwaddr>(info, vaddr))) [[unlikely]] {

                                    (*lurapro::mmio::data)[vcpu_index].d.insert(luramas::blocks::mmio::data(vaddr, reinterpret_cast<lurapro::inst *>(userdata)->inst.real_pc));
                              }
                              return;
                        }
                  } // namespace x86
            } // namespace arch

            /* On Inst execute validate it or no */
            static void __cdecl first_exec(std::uint32_t vcpu_index, void *userdata) {

                  const auto b = reinterpret_cast<lurapro::block *>(userdata);
                  auto &inst = b->insts.front();
#ifdef QEMU_PLUGIN_DEBUG
                  //   std::printf("VCPU[%d][%llu] %s \n", vcpu_index, inst.inst.pc, inst.DEBUG_DISM);
#endif
                  process::inst::first(vcpu_index, inst);
                  return;
            }
            static void __cdecl exec(std::uint32_t vcpu_index, void *userdata) {

                  process::inst::inst(vcpu_index, reinterpret_cast<lurapro::inst *>(userdata));
                  return;
            }

      } // namespace inst

      namespace vcpus {

            /* Init globals values on VCPU inits */
            static void __cdecl init(qemu_plugin_id_t id, std::uint32_t vcpu_index) {

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
                  if (lurapro::vcpu::vcpu_states->size() <= vcpu_index) {
                        lurapro::vcpu::vcpu_states->resize(vcpu_index + 1u);
                  }
                  if (lurapro::interrupts::ints->size() <= vcpu_index) {
                        lurapro::interrupts::ints->resize(vcpu_index + 1u);
                  }
                  if (lurapro::prevd_jumps_set->size() <= vcpu_index) {
                        lurapro::prevd_jumps_set->resize(vcpu_index + 1u);
                        (*lurapro::prevd_jumps_set)[vcpu_index].reserve(config::MAX_BUFFER_N_SET);
                  }
                  if (lurapro::mmio::data->size() <= vcpu_index) {
                        lurapro::mmio::data->resize(vcpu_index + 1u);
                        auto &ptr = (*lurapro::mmio::data)[vcpu_index];
                        ptr.d.reserve(config::MAX_BUFFER_N_SET);
                        ptr.file = std::ofstream(std::string(config::directory) + config::savemmio_name + std::to_string(vcpu_index) + config::extension, std::ios::binary);
                  }
                  if (lurapro::save::save_jmp_locs->size() <= vcpu_index) {
                        lurapro::save::save_jmp_locs->resize(vcpu_index + 1u);
                        (*lurapro::save::save_jmp_locs)[vcpu_index] = std::ofstream(std::string(config::directory) + config::savelocs_name + std::to_string(vcpu_index) + config::extension, std::ios::binary);
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

            /* Discontinuity callback */
            static void __cdecl discon(qemu_plugin_id_t id, std::uint32_t vcpu_index, enum qemu_plugin_discon_type type, uint64_t from_pc, uint64_t to_pc) {

#ifdef QEMU_PLUGIN_DELAY_CBS
                  if (!lurapro::start_cbs.load(std::memory_order_relaxed)) {
                        return;
                  }
#endif
                  auto t = luramas::blocks::interrupts::type::EXCEPTION;
                  switch (type) {
                        case qemu_plugin_discon_type::QEMU_PLUGIN_DISCON_HOSTCALL: {
                              t = luramas::blocks::interrupts::type::ETC;
                              break;
                        }
                        case qemu_plugin_discon_type::QEMU_PLUGIN_DISCON_INTERRUPT: {
                              t = luramas::blocks::interrupts::type::INTERUPT;
                              break;
                        }
                        case qemu_plugin_discon_type::QEMU_PLUGIN_DISCON_EXCEPTION: {
                              t = luramas::blocks::interrupts::type::EXCEPTION;
                              break;
                        }
                        default: {
                              break;
                        }
                  }
                  auto &vec = (*lurapro::interrupts::ints)[vcpu_index];
                  if (vec.size() >= vec.capacity()) {
                        vec.reserve(!vec.capacity() ? 1024u : vec.capacity() * 2u); /* Grow *2 */
                  }
                  vec.emplace_back(luramas::blocks::interrupts::interrupt(t, to_pc, from_pc, lurapro::translation::global_block_id, vcpu_index));
                  return;
            }

            /* Flushes graveyard */
            static void __cdecl tb_flush(qemu_plugin_id_t id) {

#ifdef QEMU_PLUGIN_DELAY_CBS
                  if (!lurapro::start_cbs.load(std::memory_order_relaxed)) {
                        return;
                  }
#endif
                  std::unique_lock<std::shared_mutex> lock(*lurapro::tbmutex);
                  if (lurapro::translation::block_graveyard) {
                        for (const auto &i : *lurapro::translation::block_graveyard) {
                              i->write(*lurapro::save::save);
                        }
                        lurapro::translation::block_graveyard->clear();
                  }
                  if (lurapro::interrupts::ints) {
                        for (auto &i : *lurapro::interrupts::ints) {
                              luramas::blocks::interrupts::write(*lurapro::save::save, i);
                              i.clear();
                        }
                  }
                  if (lurapro::vcpu::vcpu_states) {
                        for (auto &i : *lurapro::vcpu::vcpu_states) {
                              luramas::blocks::vcpu::write(*lurapro::save::save, i);
                              i.clear();
                        }
                  }
                  return;
            }

            /* Called when VCPU idles (used for determining cpu kick edges) */
            static void __cdecl idle(qemu_plugin_id_t id, std::uint32_t vcpu_index) {

#ifdef QEMU_PLUGIN_DELAY_CBS
                  if (!lurapro::start_cbs.load(std::memory_order_relaxed)) {
                        return;
                  }
#endif
#ifdef QEMU_PLUGIN_DEBUG
                  std::printf("VCPU[%d] Idled\n", vcpu_index);
#endif

                  auto &vec = (*lurapro::vcpu::vcpu_states)[vcpu_index];
                  if (vec.size() >= vec.capacity()) {
                        vec.reserve(!vec.capacity() ? 1024u : vec.capacity() * 2u); /* Grow *2 */
                  }
                  auto &curr_pc = (*lurapro::curr_pc)[vcpu_index];
                  vec.emplace_back(luramas::blocks::vcpu::captured_block_state(curr_pc.has_value(), luramas::blocks::vcpu::state::PAUSED, vcpu_index, curr_pc.value_or(0u), lurapro::translation::global_block_id));
                  curr_pc = std::nullopt;
                  return;
            }

            /* Called when VCPU resumes (used for determining cpu kick edges) */
            static void __cdecl resume(qemu_plugin_id_t id, std::uint32_t vcpu_index) {

#ifdef QEMU_PLUGIN_DELAY_CBS
                  if (!lurapro::start_cbs.load(std::memory_order_relaxed)) {
                        return;
                  }
#endif
#ifdef QEMU_PLUGIN_DEBUG
                  std::printf("VCPU[%d] Resumed\n", vcpu_index);
#endif

                  auto &vec = (*lurapro::vcpu::vcpu_states)[vcpu_index];
                  if (vec.size() >= vec.capacity()) {
                        vec.reserve(!vec.capacity() ? 1024u : vec.capacity() * 2u); /* Grow *2 */
                  }
                  auto &curr_pc = (*lurapro::curr_pc)[vcpu_index];
                  vec.emplace_back(luramas::blocks::vcpu::captured_block_state(curr_pc.has_value(), luramas::blocks::vcpu::state::RESUME, vcpu_index, curr_pc.value_or(0u), lurapro::translation::global_block_id));
                  curr_pc = std::nullopt;
                  return;
            }

      } // namespace vcpus

      namespace tb {

            /* Translation block execution CB */
            static void __cdecl exec(std::uint32_t vcpu_index, void *userdata) {

                  auto &djmps = (*lurapro::prevd_jumps)[vcpu_index];
                  if (djmps.empty()) [[likely]] {
                        return;
                  }
                  auto &jset = (*lurapro::prevd_jumps_set)[vcpu_index];
                  jset.insert(std::make_move_iterator(djmps.begin()), std::make_move_iterator(djmps.end()));
                  djmps.clear();
                  if (jset.size() > config::MAX_BUFFER_N_SET) [[unlikely]] {

                        /* Save edges */
                        auto nodes_to_save = std::move(jset);
                        jset.clear();
                        boost::asio::post(*lurapro::save::pool, [to_save = std::move(nodes_to_save), vcpu_index]() mutable {
                              luramas::blocks::edges::save(to_save, (*lurapro::save::save_jmp_locs)[vcpu_index]);
                        });
                  }
                  if ((*lurapro::mmio::data)[vcpu_index].d.size() > config::MAX_BUFFER_N_SET) [[unlikely]] {

                        /* Save mmio data */
                        boost::asio::post(*lurapro::save::pool, [vcpu_index]() mutable {
                              auto &data = (*lurapro::mmio::data)[vcpu_index];
                              luramas::blocks::mmio::write(data.file, boost::container::vector<luramas::blocks::mmio::data>(data.d.begin(), data.d.end()));
                              data.d.clear();
                        });
                  }
                  return;
            }

            /* Translate per block CB */
            static void __cdecl trans(qemu_plugin_id_t id, qemu_plugin_tb *tb) {

#ifdef QEMU_PLUGIN_DELAY_CBS
                  if (!lurapro::start_cbs.load(std::memory_order_relaxed)) {
                        return;
                  }
#endif
                  const auto instc = lurapro::qemu_w<qemu_plugin_tb_n_insns>(tb);
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
                        lurapro::capstone_handles::handle h;
                        for (auto i = 0u; i < instc; ++i) {

                              const auto insn = lurapro::qemu_w<qemu_plugin_tb_get_insn>(tb, i);
                              const auto len = lurapro::qemu_w<qemu_plugin_insn_size>(insn);
                              if (!len) {
                                    continue;
                              }

                              /* Set PC */
                              const auto pc = static_cast<luramas::profile::address>(lurapro::qemu_w<qemu_plugin_insn_vaddr>(insn));
                              if (!fhas_pc) {
                                    fhas_pc = true;
                                    b->loc = pc;
                              }
                              b->insts.emplace_back();
                              auto &inst = b->insts.back();

                              /* Write bytes to TB */
                              inst.inst.bytes.resize(len);
                              lurapro::qemu_w<qemu_plugin_insn_data>(insn, inst.inst.bytes.data(), len);

                              /* Inst incomplete data */
                              inst.inst.pc = pc;
                              lurapro::qemu_w<qemu_plugin_register_vcpu_insn_exec_cb>(insn, !i ? inst::first_exec : inst::exec, qemu_plugin_cb_flags::QEMU_PLUGIN_CB_NO_REGS, !i ? reinterpret_cast<void *>(b.get()) : reinterpret_cast<void *>(&b->insts[i]));

                              /* Memwrites */
                              switch (config::arch) {
                                    case luramas::blocks::arch::x86: {
                                          lurapro::qemu_w<qemu_plugin_register_vcpu_mem_cb>(insn, inst::arch::x86::mem_write, qemu_plugin_cb_flags::QEMU_PLUGIN_CB_NO_REGS, qemu_plugin_mem_rw::QEMU_PLUGIN_MEM_RW, reinterpret_cast<void *>(&b->insts[i]));
                                          break;
                                    }
                                    default: {
                                          break;
                                    }
                              }

                              /* Get mode */
                              if (!i) {
                                    const auto &[mode, handle] = helpers::get_mode(lurapro::qemu_w<qemu_plugin_insn_disas>(insn), inst);
                                    h = handle;
                                    b->interpretation_id = mode;
                              }

                              if (x86_insn(*helpers::get_op_id(h, inst)) == x86_insn::X86_INS_WRMSR) {
                                    lurapro::qemu_w<qemu_plugin_register_vcpu_insn_exec_cb>(insn, inst::debug::print_regs, qemu_plugin_cb_flags::QEMU_PLUGIN_CB_R_REGS, !i ? reinterpret_cast<void *>(b.get()) : reinterpret_cast<void *>(&b->insts[i]));
                              }
#ifdef QEMU_PLUGIN_DEBUG
                              helpers::disassemble(h, inst, inst.DEBUG_DISM, sizeof(inst.DEBUG_DISM));
#endif
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
                        lurapro::qemu_w<qemu_plugin_register_vcpu_tb_exec_cb>(tb, tb::exec, qemu_plugin_cb_flags::QEMU_PLUGIN_CB_NO_REGS, nullptr);

                        std::unique_lock<std::shared_mutex> lock(*lurapro::tbmutex);
                        b->id = lurapro::translation::global_block_id++;
                        if (lurapro::translation::block_graveyard->size() >= lurapro::translation::block_graveyard->capacity()) {
                              lurapro::translation::block_graveyard->reserve(!lurapro::translation::block_graveyard->capacity() ? 1024u : lurapro::translation::block_graveyard->capacity() * 2u);
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
      } // namespace tb

      /* On vcpu exit CB save instruction data */
      static void __cdecl at_exit(qemu_plugin_id_t id, void *userdata) {

            if (lurapro::save::pool) {
                  lurapro::save::pool->join();
            }
            for (const auto &[_, b] : *lurapro::translation::blocks) {
                  b->write(*lurapro::save::save);
            }
            for (const auto &i : *lurapro::translation::block_graveyard) {
                  i->write(*lurapro::save::save);
            }
            for (const auto &i : *lurapro::interrupts::ints) {
                  luramas::blocks::interrupts::write(*lurapro::save::save, i);
            }
            for (const auto &i : *lurapro::vcpu::vcpu_states) {
                  luramas::blocks::vcpu::write(*lurapro::save::save, i);
            }
            for (const auto &i : *lurapro::mmio::data) {
                  if (i.d.empty()) {
                        continue;
                  }
                  luramas::blocks::mmio::write(*lurapro::save::save, boost::container::vector<luramas::blocks::mmio::data>(i.d.begin(), i.d.end()));
            }
            for (auto idx = 0u; idx < lurapro::prevd_jumps_set->size(); ++idx) {
                  luramas::blocks::edges::save((*lurapro::prevd_jumps_set)[idx], (*lurapro::save::save_jmp_locs)[idx]);
            }
            lurapro::destroy();
            return;
      }
} // namespace cbs

#ifdef QEMU_PLUGIN_DELAY_CBS
/* Listen for command to enable expensive Cbs */
void cmd_listener() {

      std::string input("");
      std::printf("Enter 'x' to enable expensive Cbs\n");
      do {
            std::cin >> input;
            if (input == "x") {
                  std::printf("Enabled Cbs\n");
                  lurapro::start_cbs.store(true);
                  break;
            }
      } while (true);
      return;
}
#endif

/* Main plugin install */
extern "C" QEMU_PLUGIN_EXPORT std::int32_t __cdecl qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {

      lurapro::init();
#ifdef _WIN32
      lurapro::mod = LoadLibraryA("qemu-system-x86_64.exe");
#endif
      lurapro::qemu_w<qemu_plugin_register_vcpu_init_cb>(id, cbs::vcpus::init);
      lurapro::qemu_w<qemu_plugin_register_atexit_cb>(id, cbs::at_exit, nullptr);

      /* Can optionaly start being executed later */
      {
#ifdef QEMU_PLUGIN_DELAY_CBS
            std::thread(cmd_listener).detach();
#endif
            lurapro::qemu_w<qemu_plugin_register_vcpu_tb_trans_cb>(id, cbs::tb::trans);
            lurapro::qemu_w<qemu_plugin_register_flush_cb>(id, cbs::vcpus::tb_flush);
            lurapro::qemu_w<qemu_plugin_register_vcpu_idle_cb>(id, cbs::vcpus::idle);
            lurapro::qemu_w<qemu_plugin_register_vcpu_resume_cb>(id, cbs::vcpus::resume);
            lurapro::qemu_w<qemu_plugin_register_vcpu_discon_cb>(id, qemu_plugin_discon_type::QEMU_PLUGIN_DISCON_ALL, cbs::vcpus::discon);
      }
      return 0;
}