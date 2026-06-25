#pragma once
#include "../boostpp/vector.hpp"
#include <cstdint>
#include <fstream>
#include <istream>

namespace luramas::basic_info {

      template <std::uint8_t MAX_LEN>
      using inst_bytes = boost::fixed_vector<std::uint8_t, MAX_LEN, std::uint8_t>; /* Instruction bytes */
      using address = std::uintptr_t;

      template <std::uint8_t MAX_LEN>
      struct inst {

            bool fvalid_prev_real_pc = true; /* Is prev_real_pc valid? */
            address pc = 0u;                 /* Virtual pc */
            address real_pc = 0u;            /* Logical pc */
            address prev_real_pc = 0u;       /* Previous logical PC */
            std::uint8_t vcpu = 0u;          /* Virtual CPU it got executed on */
            inst_bytes<MAX_LEN> bytes;       /* Bytes */

            /* Contains bytes? */
            inline bool contains(const inst_bytes<MAX_LEN> &b) const {

                  return b.size() <= this->bytes.size() && std::equal(b.begin(), b.end(), this->bytes.data());
            }

            /* Read/Write */
            inline void read(std::ifstream &ifs) {
                  ifs.read(reinterpret_cast<char *>(&this->fvalid_prev_real_pc), sizeof(this->fvalid_prev_real_pc));
                  ifs.read(reinterpret_cast<char *>(&this->pc), sizeof(this->pc));
                  ifs.read(reinterpret_cast<char *>(&this->real_pc), sizeof(this->real_pc));
                  ifs.read(reinterpret_cast<char *>(&this->prev_real_pc), sizeof(this->prev_real_pc));
                  ifs.read(reinterpret_cast<char *>(&this->vcpu), sizeof(this->vcpu));
                  std::size_t bytes_len = 0u;
                  ifs.read(reinterpret_cast<char *>(&bytes_len), sizeof(bytes_len));
                  this->bytes.resize(bytes_len);
                  if (bytes_len > 0u) {
                        ifs.read(reinterpret_cast<char *>(this->bytes.data()), bytes_len);
                  }
                  return;
            }
            inline void write(std::ofstream &ofs) const {
                  ofs.write(reinterpret_cast<const char *>(&this->fvalid_prev_real_pc), sizeof(this->fvalid_prev_real_pc));
                  ofs.write(reinterpret_cast<const char *>(&this->pc), sizeof(this->pc));
                  ofs.write(reinterpret_cast<const char *>(&this->real_pc), sizeof(this->real_pc));
                  ofs.write(reinterpret_cast<const char *>(&this->prev_real_pc), sizeof(this->prev_real_pc));
                  ofs.write(reinterpret_cast<const char *>(&this->vcpu), sizeof(this->vcpu));
                  const std::size_t bytes_len = this->bytes.size();
                  ofs.write(reinterpret_cast<const char *>(&bytes_len), sizeof(bytes_len));
                  if (bytes_len > 0u) {
                        ofs.write(reinterpret_cast<const char *>(this->bytes.data()), bytes_len);
                  }
                  return;
            }
      };
} // namespace luramas::basic_info