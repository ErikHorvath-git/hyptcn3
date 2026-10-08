.PHONY: build test check lab-up lab-status lab-stop lab-test lab-traffic-stop

build:
	$(MAKE) -C vmicollect

test: build
	$(MAKE) -C vmicollect test
	python3 -m pytest -q

check:
	bash scripts/check_claims.sh

lab-up:
	python3 scripts/labctl.py up

lab-status:
	python3 scripts/labctl.py status

lab-stop:
	python3 scripts/labctl.py stop

lab-test:
	python3 scripts/lab_smoke.py

lab-traffic-stop:
	python3 scripts/labctl.py traffic-stop
