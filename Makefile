.PHONY: demo clean

PYTHON ?= python3
OUTDIR := demo/out
INPUT := data/samples/toy.jsonl

demo:
	$(PYTHON) -m blackice run \
		--input $(INPUT) \
		--outdir $(OUTDIR) \
		--audit-mode warn

clean:
	rm -rf $(OUTDIR)
