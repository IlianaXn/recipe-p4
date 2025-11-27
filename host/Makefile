# Makefile

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDFLAGS  ?=
INCLUDES ?= -Isrc

SRC_DIR  := src
BIN_DIR  := bin

COMMON_SRCS := $(SRC_DIR)/socket_utils.cpp

HOST_LOOP_HDRS := $(SRC_DIR)/socket_utils.hpp $(SRC_DIR)/packet_format.hpp
HOST_TEST_HDRS := $(SRC_DIR)/socket_utils.hpp $(SRC_DIR)/packet_format_test.hpp

BINS := $(BIN_DIR)/host_loop \
        $(BIN_DIR)/host_test

.PHONY: all clean

all: $(BIN_DIR) $(BINS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# -------------------------
# host_loop (uses packet_format.hpp)
# -------------------------
$(BIN_DIR)/host_loop: $(SRC_DIR)/host_loop.cpp $(COMMON_SRCS) $(HOST_LOOP_HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SRC_DIR)/host_loop.cpp $(COMMON_SRCS) $(LDFLAGS)

# -------------------------
# host_test (uses packet_format_test.hpp)
# -------------------------
$(BIN_DIR)/host_test: $(SRC_DIR)/host_test.cpp $(COMMON_SRCS) $(HOST_TEST_HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SRC_DIR)/host_test.cpp $(COMMON_SRCS) $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)