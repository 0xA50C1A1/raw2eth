cmake_minimum_required(VERSION 3.5)

find_path(PCAP_INCLUDE_DIR
  NAMES pcap.h
  PATH_SUFFIXES include
)  

find_library(PCAP_LIBRARY
  NAMES pcap
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG PCAP_LIBRARY PCAP_INCLUDE_DIR)

if(PCAP_FOUND)
  add_library(PCAP::PCAP UNKNOWN IMPORTED)

  set_target_properties(PCAP::PCAP PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
