#include "../config.hpp"
#include "../shared/fast_groups.hpp"
#include "../shared/luramas/basic_info.hpp"
#include "../shared/luramas/blocks.hpp"
#include "../shared/luramas/blocks_flags.hpp"
#include "../shared/x86_regs.hpp"
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/sort/pdqsort/pdqsort.hpp>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <filesystem>
#include <fstream>
#include <ranges>

using block = boost::shared_ptr<luramas::blocks::block<config::MAX_LEN>>;                                                    /* Block PTR */
using edge_map = boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>>; /* Real PC -> { Real PC Edges } */
using cap_map = boost::unordered_flat_map<luramas::blocks::interpretation_mode, std::pair<csh, cs_insn *>>;                  /* Capstone map Interp mode -> { CS DATA } */
struct save_data {
      boost::unordered_flat_set<luramas::blocks::edges::jmp_loc, luramas::blocks::edges::jmp_loc_hash> edge_map; /* Edge Map */
      boost::unordered_flat_map<luramas::profile::address, block> block_map;                                     /* Block/node map */
      boost::container::vector<luramas::blocks::interrupts::interrupt> interrupts;                               /* VCPU interrupts */
      boost::container::vector<luramas::blocks::vcpu::captured_block_state> block_states;                        /* Block states */
      boost::container::vector<luramas::blocks::mmio::data> mmio;                                                /* MMIO */
};
struct compiled_data {
      boost::container::vector<block> sorted_blocks_global_id;                                                                                                  /* Sorted blocks by global ID */
      boost::unordered_flat_map<luramas::profile::address, boost::container::vector<std::pair<block, luramas::blocks::inst_data<config::MAX_LEN> *>>> inst_map; /* Instruction [VAddr -> { Inst PTR }] */
};
using Graph = boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, block>;

namespace analysis {

      struct edges_data {

            edge_map successors;  /* Src -> Dest */
            edge_map predecessor; /* Dest -> Src */

            /* Emits edge */
            inline void emit(const luramas::profile::address dest_real_pc, const luramas::profile::address src_real_pc) {
                  this->successors[src_real_pc].insert(dest_real_pc);
                  this->predecessor[dest_real_pc].insert(src_real_pc);
                  return;
            }

            /* Generate a label given address */
            inline static std::string gen_label(const luramas::profile::address &addr) {
                  return "LABEL_" + std::to_string(addr);
            }
      };

      /* Disassemble data */
      inline bool disassemble(const block &b, const luramas::blocks::inst_data<config::MAX_LEN> *inst, cap_map &cmap) {
            const auto *tmp_ptr = inst->inst.bytes.data();
            std::size_t ts = inst->inst.bytes.size();
            std::uint64_t ta = inst->inst.pc;
            auto &[capstone_handle, insn] = cmap[b->interpretation_id];
            return cs_disasm_iter(capstone_handle, &tmp_ptr, &ts, &ta, insn);
      }

      /* 
        Analyze edges based on these hueristics:
        
        * Discontinuities based on the insts located at the curr block time of execution
        * Prev addr -> Curr address
      */
      inline void analyze(edges_data &buffer, const save_data &data, compiled_data &cd, cap_map &capmap) {

            boost::unordered_flat_map<luramas::profile::address, luramas::blocks::inst_data<config::MAX_LEN> *> data_map;

            /* VCPUs */
            std::size_t vcpus_idx = 0u;
            boost::container::vector<luramas::blocks::vcpu::state> vcpu_states;
            vcpu_states.resize(cd.sorted_blocks_global_id.front()->vcpu_n);

            /* Interrupts */
            std::size_t ints_idx = 0u;

            for (auto &b : cd.sorted_blocks_global_id) {

                  /* Set current insts (SMCs get handled by QEMU which a new block would have been created down the road) */
                  const auto bglobal_id = b->id;
                  for (auto &i : b->insts) {
                        if (!i.fvalid) {
                              continue;
                        }
                        data_map[i.inst.pc] = &i;
                        buffer.emit(i.inst.real_pc, i.inst.prev_real_pc);
                  }

                  /* VCPUs */
                  if (vcpus_idx < data.block_states.size()) {

                        auto bs = data.block_states[vcpus_idx];
                        std::cout << " intr.curr_global_block_id " << bs.curr_global_block_id << " " << bglobal_id << std::endl;
                        while (bs.curr_global_block_id <= bglobal_id) {
                              vcpu_states[bs.vcpu] = bs.k;
                              if (++vcpus_idx >= data.block_states.size()) {
                                    break;
                              }
                              bs = data.block_states[vcpus_idx];
                        }
                  }

                  /* INTs */
                  if (ints_idx < data.interrupts.size()) {

                        auto intr = data.interrupts[ints_idx];
                        while (intr.curr_global_block_id <= bglobal_id) {
                              buffer.emit(data_map[intr.dst]->inst.real_pc, data_map[intr.src]->inst.real_pc);
                              if (++ints_idx >= data.interrupts.size()) {
                                    break;
                              }
                              intr = data.interrupts[++ints_idx];
                        }
                  }
            }
            return;
      }

      /* Analyze compiled data */
      inline void analyze(compiled_data &cd, save_data &data) {

            for (auto &[_, b] : data.block_map) {
                  for (auto &i : b->insts) {
                        cd.inst_map[i.inst.pc].emplace_back(std::make_pair(b, &i));
                  }
            }

            /* sorted_blocks_global_id */
            {
                  cd.sorted_blocks_global_id.reserve(data.block_map.size());
                  std::ranges::copy(data.block_map | std::views::values, std::back_inserter(cd.sorted_blocks_global_id));
                  boost::sort::pdqsort(cd.sorted_blocks_global_id.begin(), cd.sorted_blocks_global_id.end(), [](const auto &a, const auto &b) { return a->id < b->id; });
            }

            /* Interrupts sort by block ID */
            boost::sort::pdqsort(data.interrupts.begin(), data.interrupts.end(), [](const auto &a, const auto &b) { return a.curr_global_block_id < b.curr_global_block_id; });

            /* Block States sort by block ID */
            boost::sort::pdqsort(data.block_states.begin(), data.block_states.end(), [](const auto &a, const auto &b) { return a.curr_global_block_id < b.curr_global_block_id; });

            return;
      }
} // namespace analysis

/* Export graphviz to file while using nodes as label strings. */
//void export_graphviz(const Graph &g, const std::string &file, const std::unordered_map<luramas::profile::address, std::string> &nodes) {
//
//      std::ofstream out(file);
//      const auto vertex_writer = [&](std::ostream &os, const Graph::vertex_descriptor &vd) {
//            const auto &block_ptr = g[vd];
//
//            os << "[label=\"";
//            if (block_ptr && !block_ptr->insts.empty()) {
//
//                  const auto addr = block_ptr->insts.front().inst.real_pc;
//                  if (const auto it = nodes.find(addr); it != nodes.end()) {
//                        os << it->second;
//                  } else {
//                        os << "Block @ 0x" << std::hex << addr;
//                  }
//            } else {
//                  os << "Unknown Block";
//            }
//            os << "\"]";
//      };
//      boost::write_graphviz(out, g, vertex_writer, boost::default_writer());
//      return;
//}

#include <windows.h>
void copyToClipboard(const std::string &text) {
      if (!OpenClipboard(nullptr)) {
            return;
      }

      EmptyClipboard();
      HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
      if (!hGlob) {
            CloseClipboard();
            return;
      }

      char *pGlob = static_cast<char *>(GlobalLock(hGlob));
      memcpy(pGlob, text.c_str(), text.size() + 1);
      GlobalUnlock(hGlob);
      SetClipboardData(CF_TEXT, hGlob);
      CloseClipboard();
      return;
}

/* Analyze block flags */
void init_flags(const analysis::edges_data &edges, const save_data &data, compiled_data &cd, cap_map &capmap) {

      /* Misc flags */
      for (auto &[addr, b] : data.block_map) {

            if (b->insts.empty()) {
                  continue;
            }
            auto &finst = b->insts.front();

            /* Entry */
            {
                  luramas::blocks::flags::finsts finsts(finst.flags);
                  finsts.fentry = !finst.inst.vcpu && !finst.inst.real_pc;
            }
            const auto valid = finst.fvalid;
            if (!valid) {
                  continue;
            }

            /* Misc Execution flags */
            for (auto &i : b->insts) {
                  luramas::blocks::flags::finsts finsts(i.flags);
                  finsts.fexecuted = i.fvalid;
                  finsts.fself_modified = b->fretranslated;
                  finsts.fexited = !finsts.fexecuted && !finsts.fself_modified;
            }
      }

      /* Go through each instruction */
      for (auto &[addr, b] : data.block_map) {

            for (auto &i : b->insts) {

                  /* Dissassemble */
                  if (!analysis::disassemble(b, &i, capmap)) {
                        continue;
                  }
                  const auto &[capstone_handle, insn] = capmap[b->interpretation_id];

                  luramas::blocks::flags::finsts finsts(i.flags);

                  /* Flag branching data with targeted architecture */
                  switch (luramas::blocks::interp_mode_to_arch(b->interpretation_id)) {
                        case luramas::blocks::arch::x86: {

                              finsts.fbranching = luramas::fast_groups::is_jmp(x86_insn(insn->id)) || luramas::fast_groups::is_call(x86_insn(insn->id)) || luramas::fast_groups::is_return(x86_insn(insn->id));
                              finsts.fconditional_jump = luramas::fast_groups::is_jmp(x86_insn(insn->id)) && !luramas::fast_groups::is_not_conditional_jmp(x86_insn(insn->id));
                              if (luramas::fast_groups::is_jmp(x86_insn(insn->id)) || luramas::fast_groups::is_call(x86_insn(insn->id))) {

                                    const auto &det = insn->detail->x86;
                                    finsts.fref = det.op_count == 1u && det.operands[0u].type == X86_OP_IMM;
                              }
                              break;
                        }
                        default: {
                              throw std::runtime_error("Unsupported Arch");
                        }
                  }

                  /* See if conditional branch was taken by seeing if next instruction is not in one of the edges */
                  const auto it = edges.successors.find(i.inst.real_pc);
                  if (it == edges.successors.end()) {
                        continue;
                  }
                  const auto &binst = b->insts.back();
                  for (const auto &rdest : it->second) {

                        const auto bit = data.block_map.find(rdest);
                        if (bit == data.block_map.end() || bit->second->insts.empty()) {
                              continue;
                        }
                        const auto taken = binst.inst.bytes.size() + binst.inst.pc != bit->second->loc;
                        if (finsts.fbranching) {
                              finsts.fother_branch_edge = taken;
                        }
                        if (finsts.fconditional_jump) {
                              finsts.ftaken_condbranch = taken;
                        }
                  }
            }
      }
      return;
}

/* Merge block src into dest */
void merge_block(boost::unordered_flat_map<luramas::profile::address, block> &bmap, block &dest, block &src) {

      /* Safety check */
      if (!dest || !src) {
            return;
      }
      const auto it = bmap.find(src->loc);
      if (it == bmap.end()) {
            return;
      }
      dest->insts.insert(dest->insts.end(), src->insts.begin(), src->insts.end());
      dest->inst_count = dest->insts.size();
      bmap.erase(it);
      return;
}
void merge_blocks(const boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>> &emap, const boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>> &remap, boost::unordered_flat_map<luramas::profile::address, block> &bmap) {

      return;
}

std::int32_t main() {

      cap_map capmap;
      save_data data;
      compiled_data cd;
      analysis::edges_data edges;

      /* X86 capstone handles */
      {
            if (csh h; cs_open(CS_ARCH_X86, CS_MODE_16, &h) == CS_ERR_OK) {
                  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
                  cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
                  capmap[luramas::blocks::interpretation_mode::x16] = std::pair(h, cs_malloc(h));
            }
            if (csh h; cs_open(CS_ARCH_X86, CS_MODE_32, &h) == CS_ERR_OK) {
                  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
                  cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
                  capmap[luramas::blocks::interpretation_mode::x32] = std::pair(h, cs_malloc(h));
            }
            if (csh h; cs_open(CS_ARCH_X86, CS_MODE_64, &h) == CS_ERR_OK) {
                  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
                  cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
                  capmap[luramas::blocks::interpretation_mode::x64] = std::pair(h, cs_malloc(h));
            }
      }

      /* Load data */
      for (const auto &entry : std::filesystem::directory_iterator(config::SAVE_DIRECTORY)) {

            if (!entry.is_regular_file()) {
                  continue;
            }
            std::ifstream file(entry.path(), std::ios::binary);
            if (!file) {
                  std::cerr << "Failed: " << entry.path() << "\n";
                  continue;
            }
            while (file.good()) {

                  const auto k = luramas::blocks::fs::get_save_type(file, true);
                  switch (k) {
                        case luramas::blocks::save_type::block: {
                              auto block = boost::make_shared<luramas::blocks::block<config::MAX_LEN>>();
                              block->read(file);
                              data.block_map[block->insts.front().inst.real_pc] = std::move(block);
                              break;
                        }
                        case luramas::blocks::save_type::edge_map: {
                              luramas::blocks::edges::read(data.edge_map, file);
                              break;
                        }
                        case luramas::blocks::save_type::vcpu_states: {
                              luramas::blocks::vcpu::read(file, data.block_states);
                              break;
                        }
                        case luramas::blocks::save_type::interrupts: {
                              luramas::blocks::interrupts::read(file, data.interrupts);
                              break;
                        }
                        case luramas::blocks::save_type::MMIO: {
                              luramas::blocks::mmio::read(file, data.mmio);
                              break;
                        }
                        case luramas::blocks::save_type::none: {
                              file.ignore(sizeof(luramas::blocks::save_type)); /* Step */
                              break;
                        }
                        default: {
                              std::cerr << "Invalid type: " << luramas::blocks::str::to_string(k) << "\n";
                              break;
                        }
                  }
            }
      }

      analysis::analyze(cd, data);                /* Compiled data */
      analysis::analyze(edges, data, cd, capmap); /* Analyze edges */

      /* Init flags and merge blocks */
      init_flags(edges, data, cd, capmap);
      //   merge_blocks(edges, data.block_map);

      /* Disassemble nodes */
      boost::unordered_flat_set<luramas::profile::address> references_labels;  /* Labels referenced by instructions */
      boost::unordered_flat_map<luramas::profile::address, std::string> nodes; /* Address to ndoe string */
      for (const auto &[addr, b] : data.block_map) {

            for (auto idx = 0u; idx < b->insts.size(); ++idx) {

                  const auto &i = b->insts[idx];

                  luramas::blocks::flags::finsts finsts;
                  finsts.unpack(i.flags);

                  /* Dissassemble */
                  const auto *tmp_ptr = i.inst.bytes.data();
                  std::size_t ts = i.inst.bytes.size();
                  std::uint64_t ta = i.inst.pc;
                  auto &[capstone_handle, insn] = capmap[b->interpretation_id];
                  if (cs_disasm_iter(capstone_handle, &tmp_ptr, &ts, &ta, insn)) {

                        /* Flag self modified */
                        auto &str = nodes[addr];
                        if (finsts.fself_modified) {
                              str += "[V]";
                        }

                        /* Compile */
                        str += "  " + std::string(insn->mnemonic) + " ";

                        /* Add reference stack edges */
                        if (idx + 1u >= b->insts.size()) {

                              std::string refs("; { ");                /* Compiled references */
                              luramas::blocks::flag fhas_refs = false; /* Have references to multiple unique edges? */
                              luramas::blocks::flag fchanged = false;  /* Label appended to the start of the string? */
                              if (const auto &it = edges.successors.find(i.inst.real_pc); it != edges.successors.end() && it->second.size()) {

                                    for (const auto &dest : it->second) {

                                          const auto bit = data.block_map.find(dest);
                                          if (bit == data.block_map.end() || bit->second->insts.empty()) {
                                                continue;
                                          }
                                          const auto label_addr = bit->second->insts.front().inst.real_pc;
                                          if (i.inst.bytes.size() + i.inst.pc != bit->second->loc) {
                                                if (!fchanged && finsts.fref) {
                                                      str += edges.gen_label(label_addr) + " ";
                                                      fchanged = true;
                                                      references_labels.insert(label_addr);
                                                } else {
                                                      fhas_refs = true;
                                                      refs += edges.gen_label(label_addr) + " ";
                                                      references_labels.insert(label_addr);
                                                }
                                          } else if (!finsts.fref) {
                                                fhas_refs = true;
                                                refs += edges.gen_label(label_addr) + " ";
                                                references_labels.insert(label_addr);
                                          }
                                    }
                                    refs += "}";
                              }
                              if (!fchanged) {
                                    str += std::string(insn->op_str);
                              }
                              if (fhas_refs) {
                                    str += refs;
                              }
                        } else {
                              str += std::string(insn->op_str);
                        }
                        str += "\n";
                  }
            }
      }

      /* Compile */
      std::ostringstream result;

      /* Find entry block  */
      std::optional<luramas::profile::address> entry_address = std::nullopt; /* Entry address */
      for (const auto &[addr, b] : data.block_map) {
            luramas::blocks::flags::finsts f;
            if (!b->insts.empty()) {
                  f.unpack(b->insts.front().flags);
            }
            if (f.fentry) {
                  entry_address = addr;
                  break;
            }
      }

      /* Start at entry then procedurely compile based on control flow schemantics */
      if (entry_address) {

            boost::container::vector<luramas::profile::address> addr_stack = {*entry_address}; /* Address stack */
            boost::unordered_flat_set<luramas::profile::address> visited;                      /* Already visited blocks */
            do {

                  /* See if address already analyzed */
                  const auto addr = addr_stack.back();
                  addr_stack.pop_back();
                  if (visited.contains(addr)) {
                        continue;
                  }
                  visited.insert(addr);

                  /* Check block map */
                  const auto &bit = data.block_map.find(addr);
                  if (bit == data.block_map.end() || bit->second->insts.empty()) {
                        continue;
                  }

                  /* Add label */
                  const auto faddr = bit->second->insts.front().inst.real_pc;
                  if (references_labels.contains(faddr)) {
                        result << edges.gen_label(faddr) << ":\n";
                  }

                  /* Add next edges */
                  const auto &binst = bit->second->insts.back();
                  if (const auto edgmapit = edges.successors.find(binst.inst.real_pc); edgmapit != edges.successors.end()) {

                        std::optional<luramas::profile::address> next_addr = std::nullopt;

                        /* Add each edge to the stack */
                        for (const auto &dest : edgmapit->second) {

                              addr_stack.emplace_back(dest);
                              const auto &bbit = data.block_map.find(dest);
                              if (bbit == data.block_map.end()) {
                                    continue;
                              }
                              if (!next_addr && binst.inst.pc + binst.inst.bytes.size() == bbit->second->loc) {
                                    next_addr = dest;
                              }
                        }

                        /* Overwrite next address to be analyzed with the one that comes after it in the CFG */
                        if (next_addr) {
                              addr_stack.emplace_back(*next_addr);
                        }
                  }
                  result << nodes[addr];

            } while (!addr_stack.empty());
      }

      copyToClipboard(result.str());
      // Graph g;
      //
      // std::unordered_map<luramas::profile::address, Graph::vertex_descriptor> vmap;
      // for (const auto &[addr, b] : block_map) {
      //
      //       auto vd = boost::add_vertex(g);
      //       g[vd] = b;
      //
      //       vmap[addr] = vd;
      // }
      // for (const auto &edge : edge_set) {
      //
      //       auto src = vmap[edge.src_realpc];
      //       auto dst = vmap[edge.dst_realpc];
      //
      //       boost::add_edge(src, dst, g);
      // }
      // printf("REMOVING\n");
      //
      // std::cout << "block_map " << block_map.size() << "  " << boost::num_vertices(g)
      //           << std::endl;
      // export_graphviz(g, "C:\\projects\\LuraQemu\\g.dot", nodes);

      std::cin.get();
      return 0;
}