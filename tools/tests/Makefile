CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wno-unused-parameter -O2
INCLUDES := -I../../linux/include -I../../linux/xdp
SRCS     := test_core.cpp ../../linux/src/engine.cpp ../../linux/src/util.cpp \
            ../../linux/src/fw_ctl.cpp
BIN      := test_core

.PHONY: test test-sanitize clean

$(BIN): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRCS) -o $@ -pthread

test: $(BIN)
	./$(BIN)

test-sanitize:
	$(CXX) -std=c++17 -Wall -Wextra -g -O1 -fno-omit-frame-pointer \
		-fsanitize=address,undefined $(INCLUDES) $(SRCS) -o $(BIN)_san -pthread
	./$(BIN)_san

clean:
	rm -f $(BIN) $(BIN)_san
