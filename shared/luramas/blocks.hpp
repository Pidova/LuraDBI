#pragma once
#include "basic_info.hpp"
#include "profile/profile.hpp"
#include <boost/container/vector.hpp>
#include <lz4.h>

namespace luramas::blocks {

      using flag = bool;
      using flag_storage = std::uint32_t;
      enum class save_type : std::uint8_t {
            none,        /* Nothing*/
            block,       /* Block */
            edge_map,    /* Edges */
            vcpu_states, /* VCPU states */
            interrupts   /* Interrupt data */
      };
      enum class arch : std::uint8_t {
            none, /* No arch */
            x86,  /* X86 */
            ARM   /* ARM */
      };
      enum class interpretation_mode : std::uint8_t {
            none,       /* No mode */
            x16,        /* (x86) X16 */
            x32,        /* (x86) X32 */
            x64,        /* (x86) X64 */
            arm_thumb,  /* Arm Thumb */
            arm32,      /* Arm 32 bit */
            arm_mclass, /* Arm Cortex-M*/
            arm_v8      /* Arm V8 */
      };
      inline constexpr arch interp_mode_to_arch(const interpretation_mode im) {
            switch (im) {
                  case interpretation_mode::x16:
                  case interpretation_mode::x32:
                  case interpretation_mode::x64: {
                        return arch::x86;
                  }
                  case interpretation_mode::arm_thumb:
                  case interpretation_mode::arm32:
                  case interpretation_mode::arm_mclass:
                  case interpretation_mode::arm_v8: {
                        return arch::ARM;
                  }
                  default: {
                        return arch::none;
                  }
            }
      }
      namespace fs {

            inline save_type get_save_type(std::ifstream &ifs, const bool reset = false) {
                  if (!ifs.is_open()) {
                        return save_type::none;
                  }
                  const auto pos = ifs.tellg();
                  auto t = save_type::none;
                  ifs.read(reinterpret_cast<char *>(&t), sizeof(t));
                  if (reset) {
                        ifs.seekg(pos);
                  }
                  return t;
            }

      } // namespace fs
      namespace edges {

            struct jmp_loc {
                  luramas::profile::address dst_realpc = 0u; /* Dest real PC */
                  luramas::profile::address src_realpc = 0u; /* Real PC source */

                  bool operator==(const jmp_loc &o) const noexcept {
                        return this->dst_realpc == o.dst_realpc && this->src_realpc == o.src_realpc;
                  }
            };
            struct jmp_loc_hash {
                  std::size_t operator()(const jmp_loc &j) const noexcept {
                        std::size_t seed = j.src_realpc;
                        boost::hash_combine(seed, j.dst_realpc);
                        return seed;
                  }
            };

#pragma pack(push, 1)
            struct packed_jmp_loc {
                  luramas::profile::address dst_realpc;
                  luramas::profile::address src_realpc;
            };
#pragma pack(pop)

            inline void save(const boost::unordered_flat_set<jmp_loc, jmp_loc_hash> &src, std::ofstream &ofs) {

                  if (!ofs.is_open() || src.empty()) {
                        return;
                  }

                  auto type = save_type::edge_map;
                  const auto vector_size = src.size();
                  ofs.write(reinterpret_cast<const char *>(&type), sizeof(type));
                  ofs.write(reinterpret_cast<const char *>(&vector_size), sizeof(vector_size));
                  std::vector<packed_jmp_loc> staging_buf;
                  staging_buf.reserve(vector_size);
                  for (const auto &i : src) {
                        staging_buf.push_back({i.dst_realpc, i.src_realpc});
                  }

                  const auto uncompressed_size = static_cast<std::int32_t>(staging_buf.size() * sizeof(packed_jmp_loc));
                  const auto max_compressed_size = LZ4_compressBound(uncompressed_size);

                  std::vector<char> compressed_buf(max_compressed_size);
                  const auto compressed_size = LZ4_compress_fast(reinterpret_cast<const char *>(staging_buf.data()), compressed_buf.data(), uncompressed_size, max_compressed_size, 3);
                  ofs.write(reinterpret_cast<const char *>(&compressed_size), sizeof(compressed_size));
                  ofs.write(compressed_buf.data(), compressed_size);
                  return;
            }
            inline bool read(boost::unordered_flat_set<jmp_loc, jmp_loc_hash> &dest, std::ifstream &ifs) {

                  if (!ifs.is_open()) {
                        return false;
                  }

                  const auto pos = ifs.tellg();
                  if (fs::get_save_type(ifs) != save_type::edge_map) {
                        ifs.seekg(pos);
                        return false;
                  }

                  std::size_t vector_size = 0u;
                  ifs.read(reinterpret_cast<char *>(&vector_size), sizeof(vector_size));
                  if (!vector_size) {
                        return false;
                  }

                  std::int32_t compressed_size = 0;
                  ifs.read(reinterpret_cast<char *>(&compressed_size), sizeof(compressed_size));

                  std::vector<char> compressed_buf(compressed_size);
                  ifs.read(compressed_buf.data(), compressed_size);

                  const auto uncompressed_size = static_cast<std::int32_t>(vector_size * sizeof(packed_jmp_loc));
                  std::vector<packed_jmp_loc> staging_buf(vector_size);

                  const auto decompressed_bytes = LZ4_decompress_safe(compressed_buf.data(), reinterpret_cast<char *>(staging_buf.data()), compressed_size, uncompressed_size);
                  if (decompressed_bytes != uncompressed_size) {
                        ifs.seekg(pos);
                        return false;
                  }

                  dest.reserve(dest.size() + vector_size);
                  for (const auto &packed : staging_buf) {
                        dest.insert({packed.dst_realpc, packed.src_realpc});
                  }
                  return true;
            }
      } // namespace edges

      namespace interrupts {

            enum class type : std::uint8_t {
                  EXCEPTION, /* Normal exception */
                  INTERUPT,  /* Normal interupt */
                  ETC        /* Misc interupt */
            };
            struct interrupt {
                  type k = type::EXCEPTION;              /* Type of interrupt */
                  luramas::profile::address dst = 0u;    /* Destination Vaddr PC */
                  luramas::profile::address src = 0u;    /* Source Vaddr PC */
                  std::size_t curr_global_block_id = 0u; /* Current global block ID to map to the instruction where it came from  */
                  std::uint8_t vcpu = 0u;                /* VCPU */
            };
            /* Read/Write functions */
            inline void read(std::ifstream &ifs, interrupt &in) {
                  ifs.read(reinterpret_cast<char *>(&in.k), sizeof(in.k));
                  ifs.read(reinterpret_cast<char *>(&in.dst), sizeof(in.dst));
                  ifs.read(reinterpret_cast<char *>(&in.src), sizeof(in.src));
                  ifs.read(reinterpret_cast<char *>(&in.curr_global_block_id), sizeof(in.curr_global_block_id));
                  ifs.read(reinterpret_cast<char *>(&in.vcpu), sizeof(in.vcpu));
                  return;
            }
            inline bool read(std::ifstream &ifs, boost::container::vector<interrupt> &v) {

                  if (!ifs.is_open()) {
                        return false;
                  }
                  if (const auto pos = ifs.tellg(); fs::get_save_type(ifs) != save_type::interrupts) {
                        ifs.seekg(pos);
                        return false;
                  }
                  std::size_t size = 0u;
                  ifs.read(reinterpret_cast<char *>(&size), sizeof(size));
                  v.resize(size);
                  for (auto i = 0u; i < size; ++i) {
                        read(ifs, v[i]);
                  }
                  return true;
            }
            inline void write(std::ofstream &ofs, const interrupt &in) {
                  ofs.write(reinterpret_cast<const char *>(&in.k), sizeof(in.k));
                  ofs.write(reinterpret_cast<const char *>(&in.dst), sizeof(in.dst));
                  ofs.write(reinterpret_cast<const char *>(&in.src), sizeof(in.src));
                  ofs.write(reinterpret_cast<const char *>(&in.curr_global_block_id), sizeof(in.curr_global_block_id));
                  ofs.write(reinterpret_cast<const char *>(&in.vcpu), sizeof(in.vcpu));
                  return;
            }
            inline void write(std::ofstream &ofs, const boost::container::vector<interrupt> &v) {

                  if (!ofs.is_open() || v.empty()) {
                        return;
                  }
                  const auto type = save_type::interrupts;
                  ofs.write(reinterpret_cast<const char *>(&type), sizeof(type));
                  const std::size_t size = v.size();
                  ofs.write(reinterpret_cast<const char *>(&size), sizeof(size));
                  for (const auto &i : v) {
                        write(ofs, i);
                  }
                  return;
            }
      } // namespace interrupts

      namespace vcpu {

            /* When a VCPU changes state it will capture the state of all active other vcpus */
            enum class state : std::uint8_t {
                  PAUSED,
                  RESUME
            };
            struct captured_block_state {
                  state k = state::PAUSED;   /* State put in */
                  std::uint8_t vcpu = 0u;    /* Related VCPU */
                  std::size_t block_id = 0u; /* Current Block ID */
            };
            /* Read/Write functions */
            inline void read(std::ifstream &ifs, captured_block_state &s) {
                  ifs.read(reinterpret_cast<char *>(&s.k), sizeof(s.k));
                  ifs.read(reinterpret_cast<char *>(&s.vcpu), sizeof(s.vcpu));
                  ifs.read(reinterpret_cast<char *>(&s.block_id), sizeof(s.block_id));
                  return;
            }
            inline bool read(std::ifstream &ifs, boost::container::vector<captured_block_state> &s) {

                  if (!ifs.is_open()) {
                        return false;
                  }
                  const auto pos = ifs.tellg();
                  if (fs::get_save_type(ifs) != save_type::vcpu_states) {
                        ifs.seekg(pos);
                        return false;
                  }
                  std::size_t size = 0u;
                  ifs.read(reinterpret_cast<char *>(&size), sizeof(size));
                  s.resize(size);
                  for (auto i = 0u; i < size; ++i) {
                        read(ifs, s[i]);
                  }
                  return true;
            }
            inline void write(std::ofstream &ofs, const captured_block_state &s) {
                  ofs.write(reinterpret_cast<const char *>(&s.k), sizeof(s.k));
                  ofs.write(reinterpret_cast<const char *>(&s.vcpu), sizeof(s.vcpu));
                  ofs.write(reinterpret_cast<const char *>(&s.block_id), sizeof(s.block_id));
                  return;
            }
            inline void write(std::ofstream &ofs, const boost::container::vector<captured_block_state> &s) {

                  if (!ofs.is_open() || s.empty()) {
                        return;
                  }
                  const auto type = save_type::vcpu_states;
                  ofs.write(reinterpret_cast<const char *>(&type), sizeof(type));
                  const std::size_t size = s.size();
                  ofs.write(reinterpret_cast<const char *>(&size), sizeof(size));
                  for (auto i = 0u; i < size; ++i) {
                        write(ofs, s[i]);
                  }
                  return;
            }
      } // namespace vcpu

      template <std::uint8_t MAX_LEN>
      struct inst_data {

            flag_storage flags = 0u;                 /* Flags to disassemble with inst_data_flags */
            luramas::basic_info::inst<MAX_LEN> inst; /* Instruction data */
            flag valid = false;                      /* See if instruction has been executed? */
      };

      template <std::uint8_t MAX_LEN>
      struct block {

            time_t time = NULL;                                                /* Time Block was translated */
            std::size_t id = 0u;                                               /* Block ID relative to other blocs */
            flag fretranslated = false;                                        /* Has block been retranslated? */
            boost::container::vector<inst_data<MAX_LEN>> insts;                /* Instruction data translated on tb exec */
            luramas::profile::address loc = 0u;                                /* Start virtual pc  */
            std::size_t inst_count = 0u;                                       /* Instruction count in block */
            interpretation_mode interpretation_id = interpretation_mode::none; /* What is it get interpreted as? */
            std::uint8_t vcpu_n = 0u;                                          /* Count of vcpus */

            inline std::size_t end_valid() const {
                  for (auto i = 0u; i < this->insts; ++i) {
                        if (this->insts[i].valid) {
                              return i;
                        }
                  }
                  return this->inst_count - 1u;
            }

            /* Read/Write functions */
            inline bool read(std::ifstream &ifs) {
                  if (!ifs.is_open()) {
                        return false;
                  }
                  if (const auto pos = ifs.tellg(); fs::get_save_type(ifs) != save_type::block) {
                        ifs.seekg(pos);
                        return false;
                  }
                  ifs.read(reinterpret_cast<char *>(&this->time), sizeof(this->time));
                  ifs.read(reinterpret_cast<char *>(&this->id), sizeof(this->id));
                  ifs.read(reinterpret_cast<char *>(&this->fretranslated), sizeof(this->fretranslated));
                  ifs.read(reinterpret_cast<char *>(&this->loc), sizeof(this->loc));
                  ifs.read(reinterpret_cast<char *>(&this->inst_count), sizeof(this->inst_count));
                  ifs.read(reinterpret_cast<char *>(&this->interpretation_id), sizeof(this->interpretation_id));
                  ifs.read(reinterpret_cast<char *>(&this->vcpu_n), sizeof(this->vcpu_n));
                  std::size_t vector_size = 0u;
                  ifs.read(reinterpret_cast<char *>(&vector_size), sizeof(vector_size));
                  this->insts.resize(vector_size);
                  for (auto i = 0u; i < vector_size; ++i) {
                        auto &entry = this->insts[i];
                        ifs.read(reinterpret_cast<char *>(&entry.flags), sizeof(entry.flags));
                        ifs.read(reinterpret_cast<char *>(&entry.valid), sizeof(entry.valid));
                        entry.inst.read(ifs);
                  }
                  return true;
            }
            inline void write(std::ofstream &ofs) const {
                  if (!ofs.is_open()) {
                        return;
                  }
                  auto type = save_type::block;
                  ofs.write(reinterpret_cast<const char *>(&type), sizeof(type));
                  ofs.write(reinterpret_cast<const char *>(&this->time), sizeof(this->time));
                  ofs.write(reinterpret_cast<const char *>(&this->id), sizeof(this->id));
                  ofs.write(reinterpret_cast<const char *>(&this->fretranslated), sizeof(this->fretranslated));
                  ofs.write(reinterpret_cast<const char *>(&this->loc), sizeof(this->loc));
                  ofs.write(reinterpret_cast<const char *>(&this->inst_count), sizeof(this->inst_count));
                  ofs.write(reinterpret_cast<const char *>(&this->interpretation_id), sizeof(this->interpretation_id));
                  ofs.write(reinterpret_cast<const char *>(&this->vcpu_n), sizeof(this->vcpu_n));
                  const auto vector_size = static_cast<std::size_t>(this->insts.size());
                  ofs.write(reinterpret_cast<const char *>(&vector_size), sizeof(vector_size));
                  for (const auto &i : this->insts) {
                        ofs.write(reinterpret_cast<const char *>(&i.flags), sizeof(i.flags));
                        ofs.write(reinterpret_cast<const char *>(&i.valid), sizeof(i.valid));
                        i.inst.write(ofs);
                  }
                  return;
            }
      };

} // namespace luramas::blocks