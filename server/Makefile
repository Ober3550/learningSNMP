# Compiler and flags
CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Wextra -g -Iinclude -MMD -MP

# Directories
SRC_DIR = src
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Target executable and source files
TARGET = $(BUILD_DIR)/app
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))
DEPS = $(OBJS:.o=.d)

# Default rule
all: $(TARGET)
	@:

# Link object files into the final binary
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

# Compile each .cpp file into an .o file inside build/obj/
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Include auto-generated header dependencies
-include $(DEPS)

# Remove the entire build directory
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
