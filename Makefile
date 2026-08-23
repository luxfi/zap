# Lux ZAP

ZAP_DOCS ?= $(HOME)/work/lux/docs/apps/docs/content/docs/zap/reference
.PHONY: docs
docs: ## Generate the ZAP package reference (godoc) into docs.lux.network
	cd tools/docgen && GOWORK=off go run . $(ZAP_DOCS) $(CURDIR)
