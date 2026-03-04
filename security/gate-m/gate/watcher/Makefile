CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fPIC -D_GNU_SOURCE -Wno-unused-result
LDFLAGS = -shared -lpthread
TARGET  = gate_watcher.so
SRC     = gate_watcher.c

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "Built $(TARGET)"

check:
	@python3 -c "import ctypes; ctypes.CDLL('./$(TARGET)'); print('load OK')"

clean:
	rm -f $(TARGET)
