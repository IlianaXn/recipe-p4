CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude

SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin

# --- host_receive ---
HOST_RECEIVE_SRCS := $(SRC_DIR)/host_receive.cpp $(SRC_DIR)/socket_utils.cpp
HOST_RECEIVE_OBJS := $(OBJ_DIR)/host_receive.o $(OBJ_DIR)/socket_utils.o
HOST_RECEIVE_BIN  := $(BIN_DIR)/host_receive

# --- host_send ---
HOST_SEND_SRCS := $(SRC_DIR)/host_send.cpp $(SRC_DIR)/socket_utils.cpp
HOST_SEND_OBJS := $(OBJ_DIR)/host_send.o $(OBJ_DIR)/socket_utils.o
HOST_SEND_BIN  := $(BIN_DIR)/host_send

# Default target: build both binaries
all: $(HOST_RECEIVE_BIN) $(HOST_SEND_BIN)

# Build host_loop binary
$(HOST_RECEIVE_BIN): $(HOST_RECEIVE_OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Build host_test binary
$(HOST_SEND_BIN): $(HOST_SEND_OBJS) | $(BIN_DIR)
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
