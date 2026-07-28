# APIStrike — one-command Docker workflows.
# Mounts the current directory at /work so scope.yaml, findings.db and reports/
# live on your host. host.docker.internal reaches labs running on localhost.
IMAGE ?= apistrike:latest
RUN   = docker run --rm --add-host=host.docker.internal:host-gateway -v "$(PWD)":/work $(IMAGE)

.PHONY: build scan report ai-report shell help

build:            ## Build the container image
	docker build -t $(IMAGE) .

help:             ## Show apistrike CLI help
	$(RUN) --help

# Usage: make scan ARGS="http://host.docker.internal:5000 --scope scope.yaml"
scan:             ## Run a scan (pass ARGS="...")
	$(RUN) scan $(ARGS)

report:           ## Render reports/report.pdf from the findings DB
	$(RUN) report --format pdf

ai-report:        ## Render reports/ai_report.pdf (needs Ollama reachable)
	$(RUN) ai-report --format pdf --model $(MODEL) --ollama-url http://host.docker.internal:11434

shell:            ## Drop into a shell inside the container
	docker run --rm -it --add-host=host.docker.internal:host-gateway -v "$(PWD)":/work --entrypoint /bin/bash $(IMAGE)

MODEL ?= llama3.2:3b
