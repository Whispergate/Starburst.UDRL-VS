CC       := gcc
CFLAGS   := -Wall -Wextra -Werror -std=c11 -g -I include
TESTS    := test_helpers test_pe_ops test_mask_ops
BINS     := $(addprefix bin/, $(TESTS))

.PHONY: all test clean

all: $(BINS)

bin/%: %.c include/test.h include/mock_pe.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $<

test: $(BINS)
	@echo "Running tests..."
	@failed=0; \
	for t in $(BINS); do \
		echo ""; \
		$$t || failed=1; \
	done; \
	exit $$failed

clean:
	rm -rf bin
