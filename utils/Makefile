P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt

ifndef BMV2_SWITCH_EXE
	BMV2_SWITCH_EXE = simple_switch_grpc
endif

ifndef TOPO
	TOPO = topology/topology.json
endif

ifndef P4C
	P4C = p4c-bm2-ss
endif

ifndef RUN_SCRIPT
	RUN_SCRIPT = utils/mininet-setup.py
endif

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)

DEFAULT_PROG = $(wildcard *.p4)
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)

all: run

run: build
	sudo python $(RUN_SCRIPT) -t $(TOPO) -j $(DEFAULT_JSON)  -b $(BMV2_SWITCH_EXE)
stop:
	sudo mn -c

build: dirs $(compiled_json)

%.json: %.p4
	sudo $(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap *.pyc
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
