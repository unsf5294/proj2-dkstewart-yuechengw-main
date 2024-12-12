CFLAGS ?= -Wall -Wextra -Werror -g -O2 -std=gnu11
LDFLAGS ?= -lm

TEST_SERVER ?= unimelb-comp30023-2024.cloud.edu.au

SOURCE_FILES := $(wildcard *.c)
HEADER_FILES := $(wildcard *.h)

all: fetchmail

fetchmail: fetchmail.o socket.o tls_socket.o imap.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f ./*.o ./*.d fetchmail

.PHONY: format
format: $(SOURCE_FILES) $(HEADER_FILES)
	clang-format -style=file -i $(SOURCE_FILES) $(HEADER_FILES)


#########
# Tests #
#########

define test_exit_code
	$(eval $@_EXPECTED_EXIT_CODE = $(1))
	$(eval $@_COMMAND = $(2))
	echo $($@_COMMAND)
	sh -c $($@_COMMAND); \
	EXIT_CODE=$$?;\
	test $$EXIT_CODE -eq $($@_EXPECTED_EXIT_CODE) || ( \
		echo "\033[31mexited with code $$EXIT_CODE instead of $($@_EXPECTED_EXIT_CODE)\033[0m"; \
		return 1 \
	)
	echo ""
endef

.PHONY: test
test: test-retrieve test-parse test-mime test-list test-errors

.PHONY: test-retrieve
test-retrieve: fetchmail
	./fetchmail -f Test -p pass -u test@comp30023 -n 1 retrieve $(TEST_SERVER) | diff - out/ret-ed512.out
	./fetchmail -f Test -p pass -u test@comp30023 -n 2 retrieve $(TEST_SERVER) | diff - out/ret-mst.out
	./fetchmail -f Test -u test@comp30023 -p pass1 -n 1 retrieve $(TEST_SERVER) | diff - out/ret-loginfail.out
	./fetchmail -u test@comp30023 -p pass -n 1 -f Test1 retrieve $(TEST_SERVER) | diff - out/ret-nofolder.out
	./fetchmail -n 42 -u test@comp30023 -p pass -f Test retrieve $(TEST_SERVER) | diff - out/ret-nomessage.out
	./fetchmail -u test.test@comp30023 -p -p -f Test -n 1 retrieve $(TEST_SERVER) | diff - out/ret-mst.out
	./fetchmail -f 'With Space' -n 1 -u test@comp30023 -p pass retrieve $(TEST_SERVER) | diff - out/ret-mst.out
	./fetchmail -f more -p pass -u test@comp30023 -n 2 retrieve $(TEST_SERVER) | diff - out/ret-nul.out
	@echo "\033[92mPassed all retrieve tests!\033[0m"

.PHONY: test-parse
test-parse: fetchmail
	./fetchmail -f Test -p pass -n 2 -u test@comp30023 parse $(TEST_SERVER) | diff - out/parse-mst.out
	./fetchmail -f Test -n 3 -p pass -u test@comp30023 parse $(TEST_SERVER) | diff - out/parse-minimal.out
	./fetchmail -p pass -f headers -u test@comp30023 -n 2 parse $(TEST_SERVER) | diff - out/parse-caps.out
	./fetchmail -f headers -u test@comp30023 -p pass -n 3 parse $(TEST_SERVER) | diff - out/parse-nosubj.out
	./fetchmail -u test@comp30023 -n 4 -p pass -f headers parse $(TEST_SERVER) | diff - out/parse-nested.out
	./fetchmail -f headers -u test@comp30023 -n 5 -p pass parse $(TEST_SERVER) | diff - out/parse-ws.out
	./fetchmail -f more -p pass -u test@comp30023 -n 1 parse $(TEST_SERVER) | diff - out/parse-mst-tab.out
	@echo "\033[92mPassed all parse tests!\033[0m"

.PHONY: test-mime
test-mime: fetchmail
	./fetchmail -n 1 -p pass -u test@comp30023 mime $(TEST_SERVER) | diff - out/mime-ed512.out
	./fetchmail -f Test -n 2 -p pass -u test@comp30023 mime $(TEST_SERVER) | diff - out/mime-mst.out
	@echo "\033[92mPassed all mime tests!\033[0m"

.PHONY: test-list
test-list: fetchmail
	./fetchmail -p pass -u test@comp30023 -f Test list $(TEST_SERVER) | diff - out/list-Test.out
	./fetchmail -p pass -u test@comp30023 list $(TEST_SERVER) | diff - out/list-INBOX.out
	@echo "\033[92mPassed all list tests!\033[0m"

.PHONY: test-tls
test-tls: fetchmail
	./fetchmail -f Test -p pass -u test@comp30023 -n 1 -t retrieve $(TEST_SERVER) | diff - out/ret-ed512.out

.PHONY: test-errors
test-safety: fetchmail
	@$(call test_exit_code,1,"./fetchmail")
	@$(call test_exit_code,1,"./fetchmail -u")
	@$(call test_exit_code,1,"./fetchmail retrieve")
	@$(call test_exit_code,1,"./fetchmail $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -p -u retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -p a -u f -f retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -n 0 -u test@comp30023 -p pass -f Test retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -n -1 -u test@comp30023 -p pass -f Test retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -n 10000000000000000000000000000000000 -u test@comp30023 -p pass -f Test retrieve $(TEST_SERVER)")
	@$(call test_exit_code,1,"./fetchmail -n comp30023 -u test@comp30023 -p pass -f Test retrieve $(TEST_SERVER)")
	@$(call test_exit_code,3,"./fetchmail -n 1 -u test@comp30023 -p pass -f '' retrieve $(TEST_SERVER)")
	@$(call test_exit_code,3,"./fetchmail -n 1 -u test@comp30023 -p pass -f ' ' retrieve $(TEST_SERVER)")
	@$(call test_exit_code,3,"./fetchmail -n 1 -u test@comp30023 -p pass -f '🫤' retrieve $(TEST_SERVER)")
	@$(call test_exit_code,3,"./fetchmail -u f -p a retrieve ''")
	@$(call test_exit_code,3,"./fetchmail -u f -p a retrieve ' '")
	@$(call test_exit_code,3,"./fetchmail -u f -p a retrieve aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	@$(call test_exit_code,3,"./fetchmail -f Test -p $'pass\r\nCOMP30023 LOGIN inject@comp30023 pass' -u inject@comp30023 -n 1 retrieve $(TEST_SERVER)")
	@$(call test_exit_code,2,"./fetchmail -f Test -p pass -u test@comp30023 -n 1 retrieve <a-server-which-disconnects>")
	@echo "\033[92mPassed all safety tests!\033[0m"

%.o: %.c
	$(CC) $(CFLAGS) -MMD -o $@ -c $<

-include *.d
