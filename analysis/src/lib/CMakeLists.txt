set (UniSanSourceCodes
	Common.h
	UniSan.h
	UniSan.cc
	CallGraph.h
  CallGraph.cc
	SAStructs.h
	SAStructs.cc
  SafeAllocation.h
  SafeAllocation.cc
)

# Build libraries.
add_library (UniSanObj OBJECT ${UniSanSourceCodes})
add_library (UniSan SHARED $<TARGET_OBJECTS:UniSanObj>)
add_library (UniSanStatic STATIC $<TARGET_OBJECTS:UniSanObj>)

# Build executable unisan.
set (EXECUTABLE_OUTPUT_PATH ${UNISAN_BINARY_DIR})
link_directories (${UNISAN_BINARY_DIR}/lib)
add_executable(unisan ${UniSanSourceCodes})
target_link_libraries(unisan 
  LLVMAsmParser 
  LLVMSupport 
  LLVMCore 
  LLVMAnalysis
  LLVMIRReader
	UniSanStatic
  )
