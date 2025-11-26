CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude

SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin

HOST_SRCS := $(SRC_DIR)/host_loop.cpp $(SRC_DIR)/socket_utils.cpp
HOST_OBJS := $(OBJ_DIR)/host_loop.o $(OBJ_DIR)/socket_utils.o
HOST_BIN  := $(BIN_DIR)/host_loop

# Default target
all: $(HOST_BIN)

# Build binary
$(HOST_BIN): $(HOST_OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Build individual object files
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