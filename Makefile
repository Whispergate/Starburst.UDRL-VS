MFLAGS :=

.DEFAULT: all
.PHONY: all debug addflag x64 x86 clean

all:
	@ echo "[+] Compile Sleepmask"
	@ $(MAKE) $(MFLAGS) --no-print-directory -C mask
	@ echo "[+] Compile UDRL"
	@ $(MAKE) $(MFLAGS) --no-print-directory -C loader

x64:
	@ $(MAKE) --no-print-directory -C loader x64

x86:
	@ $(MAKE) --no-print-directory -C loader x86

debug: addflag all

addflag:
	@echo Sleepmask: Compiling DEBUG Build
	$(eval MFLAGS += debug)

clean:
	@ $(MAKE) clean --no-print-directory -C mask
	@ $(MAKE) clean --no-print-directory -C loader