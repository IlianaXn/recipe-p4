CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude

SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin

# --- host_loop ---
HOST_LOOP_SRCS := $(SRC_DIR)/host_loop.cpp $(SRC_DIR)/socket_utils.cpp
HOST_LOOP_OBJS := $(OBJ_DIR)/host_loop.o $(OBJ_DIR)/socket_utils.o
HOST_LOOP_BIN  := $(BIN_DIR)/host_loop

# --- host_test ---
HOST_TEST_SRCS := $(SRC_DIR)/host_test.cpp $(SRC_DIR)/socket_utils.cpp
HOST_TEST_OBJS := $(OBJ_DIR)/host_test.o $(OBJ_DIR)/socket_utils.o
HOST_TEST_BIN  := $(BIN_DIR)/host_test

# Default target: build both binaries
all: $(HOST_LOOP_BIN) $(HOST_TEST_BIN)

# Build host_loop binary
$(HOST_LOOP_BIN): $(HOST_LOOP_OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Build host_test binary
$(HOST_TEST_BIN): $(HOST_TEST_OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Build individual object files (works for host_loop.o, host_test.o, socket_utils.o)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Ensure required folders exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
