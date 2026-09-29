PROJECT = sleepmask
CCX64  := x86_64-w64-mingw32-gcc
CFLAGS := -O0 -I../common/src -I../common/include -Iinclude -w

.DEFAULT: all
.PHONY: all debug addflag bof
all: bof

debug: addflag bof

addflag:
	@echo Sleepmask: Compiling DEBUG Build
	$(eval CFLAGS += -DDEBUG)

bof: $(PROJECT).x64.o

$(PROJECT).x64.o: src/main.c
	@echo Compiling x64 BOF and patching symbols
	@$(CCX64) -c $< -o dist/$@ $(CFLAGS)
	
.PHONY: clean
clean:
	@echo Cleaning Sleepmask
	@rm -f dist/$(PROJECT).x64.o