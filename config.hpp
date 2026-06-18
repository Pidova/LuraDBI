#include "shared/luramas/blocks.hpp"

namespace config {
	 
	  /* Max edges in buffer before emitting to set */
      static constexpr auto MAX_BUFFER_EDGES = 128u;
	  
	  /* Minimum edges in set before saving */
      static constexpr auto MAX_BUFFER_EDGES_SET = MAX_BUFFER_EDGES * 32u;
	  
	  /* Maximum length per instruction */
      static constexpr auto MAX_LEN = 15u;
	  
	  /* Directory to save edge and block data */
      static constexpr auto directory = "C:\\qemudumps\\blocks\\";
	  
	  /* Save name of block data */
      static constexpr auto mainsave_name = "save";
	  
	  /* Save name of edge data */
      static constexpr auto savelocs_name = "edges_";
	  
	  /* Extension */
      static constexpr auto extension = ".lurablks";
	  
	  /* Default interpretation mode */
      static constexpr auto default_mode = luramas::blocks::interpretation_mode::x64;
	  
	   /* Target architecture */
      static constexpr auto arch = luramas::blocks::arch::x86;
} // namespace config