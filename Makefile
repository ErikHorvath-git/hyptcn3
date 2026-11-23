.PHONY: build test check lab-up lab-status lab-stop lab-test lab-traffic-stop collection-plan

build:
	$(MAKE) -C vmicollect

test: build
	$(MAKE) -C vmicollect test
	python3 -m pytest -q

check:
	bash scripts/check_claims.sh

# The single lab VM of the protocols of schema 1 and 2 (hyptcn-lab, port 18080); labctl up requires the protocol.
lab-up:
	python3 scripts/labctl.py up --protocol config/collection-v2.json

lab-status:
	python3 scripts/labctl.py status

lab-stop:
	python3 scripts/labctl.py stop

lab-test:
	python3 scripts/lab_smoke.py

lab-traffic-stop:
	python3 scripts/labctl.py traffic-stop

collection-plan:
	python3 scripts/collection.py plan
