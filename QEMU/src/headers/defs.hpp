#pragma once
#include "../../../config.hpp"
#include "../../../shared/fast_groups.hpp"
#include "../../../shared/luramas/basic_info.hpp"
#include "../../../shared/luramas/blocks.hpp"
#include "../../../shared/x86_regs.hpp"
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

      struct pending_edge {
            luramas::profile::address from = 0u;      /* From real PC */
            luramas::profile::address target_pc = 0u; /* Target Physical Address Note. Some archs only give physical address and Vaddr can be translated to a physical address */
      };
      vcpu_vec<std::optional<pending_edge>> *pending_edges = nullptr;
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

            /* Writable address to monitor */
            std::size_t size = 0u;
            luramas::profile::address base = 0u;
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

      /* Garray buffer for registers */
      thread_local GByteArray *garr_buf = nullptr;

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
                  if (!lurapro::pending_edges) {
                        lurapro::pending_edges = new vcpu_vec<std::optional<pending_edge>>();
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
                        save::save = new std::ofstream(std::string(config::SAVE_DIRECTORY) + config::SAVEMAIN_NAME + config::SAVE_EXTENSION, std::ios::binary);
                  }
                  if (!save::save_jmp_locs) {
                        save::save_jmp_locs = new vcpu_vec<std::ofstream>();
                  }
                  if (!save::pool) {
                        save::pool = new boost::asio::thread_pool(1u);
                  }
            }
#ifdef QEMU_LOG_MMIO
            {
                  if (!mmio::data) {
                        mmio::data = new vcpu_vec<mmio::mmio_data>();
                  }
            }
#endif
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
                  if (pending_edges) {
                        pending_edges->clear();
                        delete pending_edges;
                        pending_edges = nullptr;
                  }
                  if (prevd_jumps) {
                        prevd_jumps->clear();
                        delete prevd_jumps;
                        prevd_jumps = nullptr;
                  }
                  if (real_pc) {
                        delete real_pc;
                        real_pc = nullptr;
                  }
                  if (tbmutex) {
                        delete tbmutex;
                        tbmutex = nullptr;
                  }
            }
#ifdef QEMU_LOG_MMIO
            {
                  if (!mmio::data) {
                        mmio::data->clear();
                        delete mmio::data;
                        mmio::data = nullptr;
                  }
            }
#endif
            return;
      }
} // namespace lurapro