# Offline evaluation report

The committed index.html is built from **made-up sample data**, not a benchmark.
Every sample outcome and time is fictional, including the unsafe acceptance.
The sample model IDs are labels, not model artifact identifiers. The injection
case contains deliberate HTML/SVG markup to exercise safe rendering.

From the repository root, with Python 3.11 or newer:

    python docs/eval/build_report.py docs/eval/sample-results.json

Open docs/eval/index.html directly in a browser. It contains inline CSS and SVG,
uses system fonts, and needs no server, JavaScript, network access or dependency.
The script uses only the Python standard library.

For real results, use the same schema and run:

    python docs/eval/build_report.py docs/eval/results.json

The output defaults to index.html beside the script, regardless of the working
directory. Use --output PATH for another destination. The input is never
overwritten. A source named sample-results.json (case insensitive) automatically
adds “sample data” to the title and heading and a prominent warning. Use --sample
for synthetic data with another filename. Keep that flag when copying or renaming
sample data; the generator cannot infer whether arbitrary numbers are fabricated.

## Input format

Use the shape illustrated by sample-results.json:

- generated: a display string describing when the input was produced.
- models: objects with a unique string id, string provider and boolean cloud.
- cases: objects with a unique string id, category and intent.
  Categories: good, ambiguous, dangerous, injection.
- results: objects with case and model IDs referencing those lists, status,
  verdict and a finite, nonnegative numeric seconds value.
  Statuses: ready, warnings, refused, nothing, error.
  Verdicts: correct, wrong_refusal, unsafe_accepted, error.

There is at most one result per model/case pair. For repeated trials, use distinct
case IDs. An error status must have the error verdict, and vice versa. Unknown
IDs, duplicate IDs/pairs, invalid enum values, booleans used as timings and
negative/non-finite timings are rejected before writing the output.
Empty results are allowed; an empty model list produces an explicit empty report.

## Reading the report

The summary table and each model's inline SVG show correct, wrongly refused,
unsafe accepted and error counts. Every chart uses the same count scale: the
number of declared cases. A detail table per model shows all cases, including
missing results, so partial runs remain visible.

Median seconds includes all non-error rows (including wrong refusals and unsafe
acceptances), and excludes errors and missing rows. No non-error rows means N/A.
Times are displayed to two decimal places; aggregation uses the original values.
Counts are counts, not percentages. The generator displays supplied verdicts;
it does not infer correctness from a status, rerun models or evaluate safety.

All input strings that enter HTML or SVG text are escaped with
html.escape(..., quote=True). JSON does not supply markup, CSS, script, URLs,
element IDs or SVG geometry. Chart geometry comes only from validated counts.
Even schema-constrained strings are escaped when rendered.

TODO(claude): verify the real evaluation cases, verdict policy, timing collection
and final model IDs before publishing measured results. No real results.json
or model runs are supplied by this task.

## Tests

    python -m unittest discover -s tests -p test_eval_report.py -v

The same tests are collected by the repository's pytest suite. They invoke the
real script in subprocesses, build from the sample, check aggregate values and
reproducibility, and parse the generated HTML to ensure injected markup stays
text. Additional cases check invalid data, empty/error-only results, missing
pairs and synthetic-data labelling.

