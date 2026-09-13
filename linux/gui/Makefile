# Fluxx Firewall desktop panel — Linux build
#
# ImGui is vendored under imgui/ rather than taken from the distro package: the
# layout is a direct port of the Windows build, and a distro version bump is a
# silent source of "it stopped compiling" churn in code that is meant to stay a
# faithful copy. The vendored tree is upstream, unmodified, MIT.
#
# Build:
#   make            -> fluxxfw-gui
#   make install    -> /usr/local/bin/fluxxfw-gui (+ desktop entry refresh)
#   make clean

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wno-unused-parameter
CXXFLAGS += -I. -Iimgui -I../include

PKGCONFIG ?= pkg-config
GLFW_CFLAGS := $(shell $(PKGCONFIG) --cflags glfw3 2>/dev/null)
GLFW_LIBS   := $(shell $(PKGCONFIG) --libs glfw3 2>/dev/null)
ifeq ($(strip $(GLFW_LIBS)),)
  GLFW_LIBS := -lglfw -lGL
endif

CXXFLAGS += $(GLFW_CFLAGS)
LDLIBS   := $(GLFW_LIBS) -lGL -lpthread -ldl

# proc.hpp is header-only and pulls in nothing but libc, so there is no extra
# translation unit to link.
IMGUI_SRC := \
	imgui/imgui.cpp \
	imgui/imgui_draw.cpp \
	imgui/imgui_tables.cpp \
	imgui/imgui_widgets.cpp \
	imgui/imgui_impl_glfw.cpp \
	imgui/imgui_impl_opengl3.cpp

BIN := fw-gui

.PHONY: all clean install check

all: $(BIN)

$(BIN): fw_gui.cpp $(IMGUI_SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

# Report what the build will link against, so a missing GLFW is one clear line
# instead of a wall of "GLFW/glfw3.h: No such file or directory".
check:
	@echo "compiler : $(shell $(CXX) --version | head -1)"
	@echo "glfw cfl : $(GLFW_CFLAGS)"
	@echo "glfw lib : $(GLFW_LIBS)"
	@printf 'header   : ' ; \
	  if echo '#include <GLFW/glfw3.h>' | $(CXX) $(CXXFLAGS) -E - >/dev/null 2>&1; \
	    then echo present ; else echo "MISSING — apt install libglfw3-dev libgl1-mesa-dev libx11-dev" ; fi

install: $(BIN)
	install -d /usr/local/bin
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)
	@echo "installed /usr/local/bin/$(BIN)"

clean:
	rm -f $(BIN)
