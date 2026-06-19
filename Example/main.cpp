#include "../config.hpp"
#include "../shared/fast_groups.hpp"
#include "../shared/luramas/basic_info.hpp"
#include "../shared/luramas/blocks.hpp"
#include "../shared/luramas/blocks_flags.hpp"
#include "../shared/x86_regs.hpp"
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <filesystem>
#include <fstream>

using block = std::shared_ptr<luramas::blocks::block<config::MAX_LEN>>;
using Graph = boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, block>;

/* Export graphviz to file while using nodes as label strings. */
void export_graphviz(const Graph &g, const std::string &file, const std::unordered_map<luramas::profile::address, std::string> &nodes) {

      std::ofstream out(file);
      const auto vertex_writer = [&](std::ostream &os, const Graph::vertex_descriptor &vd) {
            const auto &block_ptr = g[vd];

            os << "[label=\"";
            if (block_ptr && !block_ptr->insts.empty()) {

                  const auto addr = block_ptr->insts.front().inst.real_pc;
                  if (const auto it = nodes.find(addr); it != nodes.end()) {
                        os << it->second;
                  } else {
                        os << "Block @ 0x" << std::hex << addr;
                  }
            } else {
                  os << "Unknown Block";
            }
            os << "\"]";
      };
      boost::write_graphviz(out, g, vertex_writer, boost::default_writer());
      return;
}
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
void init_flags(const boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>> &emap, const boost::unordered_flat_map<luramas::profile::address, block> &bmap, boost::unordered_flat_map<luramas::blocks::interpretation_mode, std::pair<csh, cs_insn *>> &capmap) {

      /* Misc flags */
      for (auto &[addr, b] : bmap) {

            if (b->insts.empty()) {
                  continue;
            }
            auto &finst = b->insts.front();

            /* Entry */
            {
                  luramas::blocks::flags::finsts finsts(finst.flags);
                  finsts.fentry = !finst.inst.vcpu && !finst.inst.real_pc;
            }
            const auto valid = finst.valid.load();
            if (!valid) {
                  continue;
            }

            /* Misc Execution flags */
            for (auto &i : b->insts) {
                  luramas::blocks::flags::finsts finsts(i.flags);
                  finsts.fexecuted = i.valid.load();
                  finsts.fself_modified = b->fretranslated;
                  finsts.fexited = !finsts.fexecuted && !finsts.fself_modified;
            }
      }

      /* Go through each instruction */
      for (auto &[addr, b] : bmap) {

            for (auto &i : b->insts) {

                  /* Dissassemble */
                  const auto *tmp_ptr = i.inst.bytes.data();
                  std::size_t ts = i.inst.bytes.size();
                  std::uint64_t ta = i.inst.pc;
                  auto &[capstone_handle, insn] = capmap[b->interpretation_id];
                  if (!cs_disasm_iter(capstone_handle, &tmp_ptr, &ts, &ta, insn)) {
                        break;
                  }

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
                  const auto it = emap.find(i.inst.real_pc);
                  if (it == emap.end()) {
                        continue;
                  }
                  const auto &binst = b->insts.back();
                  for (const auto &rdest : it->second) {

                        const auto bit = bmap.find(rdest);
                        if (bit == bmap.end() || bit->second->insts.empty()) {
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

      boost::unordered_flat_map<luramas::blocks::interpretation_mode, std::pair<csh, cs_insn *>> capmap; /* Capstone handle map with interp mode */

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

      const std::string path = R"(C:\qemudumps\blocks\)";

      /* Build map */
      boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>> edge_map;  /* Edge map src -> dest */
      boost::unordered_flat_map<luramas::profile::address, boost::unordered_flat_set<luramas::profile::address>> redge_map; /* Edge map dest -> src */
      boost::unordered_flat_set<luramas::blocks::edges::jmp_loc, luramas::blocks::edges::jmp_loc_hash> edge_set;            /* Edge set */
      boost::unordered_flat_map<luramas::profile::address, block> block_map;                                                /* Block/node map */
      for (const auto &entry : std::filesystem::directory_iterator(path)) {

            if (!entry.is_regular_file()) {
                  continue;
            }
            std::ifstream file(entry.path(), std::ios::binary);
            if (!file) {
                  std::cerr << "Failed: " << entry.path() << "\n";
                  continue;
            }
            while (!file.eof() && luramas::blocks::fs::get_save_type(file, true) != luramas::blocks::save_type::none) {

                  if (!luramas::blocks::edges::read(edge_set, file)) {

                        auto block = std::make_shared<luramas::blocks::block<15u>>();
                        block->read(file);
                        block_map[block->insts.front().inst.real_pc] = std::move(block);
                  }
            }
      }

      /* Build edge map */
      boost::unordered_flat_map<luramas::profile::address, std::string> labels; /* Labels realpc -> label name */
      for (const auto &i : edge_set) {
            labels[i.dst_realpc] = "LABEL_" + std::to_string(i.dst_realpc);
            edge_map[i.src_realpc].insert(i.dst_realpc);
            redge_map[i.dst_realpc].insert(i.src_realpc);
      }
      for (const auto &[_, b] : block_map) {
            if (b->insts.empty()) {
                  continue;
            }
            for (const auto &i : {b->insts.front()}) {
                  if (!block_map.contains(i.inst.prev_real_pc)) {
                        continue;
                  }
                  labels[i.inst.real_pc] = "LABEL_" + std::to_string(i.inst.real_pc);
                  edge_map[i.inst.prev_real_pc].insert(i.inst.real_pc);
                  redge_map[i.inst.real_pc].insert(i.inst.prev_real_pc);
            }
      }

      /* Init flags and merge blocks */
      init_flags(edge_map, block_map, capmap);
      merge_blocks(edge_map, redge_map, block_map);

      /* Disassemble nodes */
      boost::unordered_flat_set<luramas::profile::address> references_labels;  /* Labels referenced by instructions */
      boost::unordered_flat_map<luramas::profile::address, std::string> nodes; /* Address to ndoe string */
      for (const auto &[addr, b] : block_map) {

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
                              if (const auto &it = edge_map.find(i.inst.real_pc); it != edge_map.end() && it->second.size()) {

                                    for (const auto &dest : it->second) {

                                          const auto bit = block_map.find(dest);
                                          if (bit == block_map.end() || bit->second->insts.empty()) {
                                                continue;
                                          }
                                          const auto label_addr = bit->second->insts.front().inst.real_pc;
                                          const auto lit = labels.find(label_addr);
                                          if (lit == labels.end()) {
                                                continue;
                                          }
                                          if (i.inst.bytes.size() + i.inst.pc != bit->second->loc) {
                                                if (!fchanged && finsts.fref) {
                                                      str += lit->second + " ";
                                                      fchanged = true;
                                                      references_labels.insert(label_addr);
                                                } else {
                                                      fhas_refs = true;
                                                      refs += lit->second + " ";
                                                      references_labels.insert(label_addr);
                                                }
                                          } else if (!finsts.fref) {
                                                fhas_refs = true;
                                                refs += lit->second + " ";
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
      for (const auto &[addr, b] : block_map) {
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
                  const auto &bit = block_map.find(addr);
                  if (bit == block_map.end() || bit->second->insts.empty()) {
                        continue;
                  }

                  /* Add label */
                  const auto faddr = bit->second->insts.front().inst.real_pc;
                  if (references_labels.contains(faddr)) {
                        result << labels[faddr] << ":\n";
                  }

                  /* Add next edges */
                  const auto &binst = bit->second->insts.back();
                  if (const auto edgmapit = edge_map.find(binst.inst.real_pc); edgmapit != edge_map.end()) {

                        std::optional<luramas::profile::address> next_addr = std::nullopt;

                        /* Add each edge to the stack */
                        for (const auto &dest : edgmapit->second) {

                              addr_stack.emplace_back(dest);
                              const auto &bbit = block_map.find(dest);
                              if (bbit == block_map.end()) {
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

      return 0;
}