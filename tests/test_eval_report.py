"""Exercise the real stdlib report builder, including hostile JSON text."""
from __future__ import annotations

import copy
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs" / "eval" / "build_report.py"
SAMPLE = SCRIPT.with_name("sample-results.json")


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.rows = []
        self.cells = None
        self.cell = None
        self.text = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "tr":
            self.cells = []
        elif tag in ("td", "th"):
            self.cell = []
        if tag in {"script", "iframe", "img", "link", "object", "embed", "foreignobject"}:
            raise AssertionError(f"Unexpected active/external element: {tag}")
        for key, value in attrs:
            if key.lower().startswith("on") or key.lower() in {"src", "href", "xlink:href", "srcdoc"}:
                raise AssertionError(f"Unexpected active/external attribute: {key}")

    def handle_data(self, value):
        self.text.append(value)
        if self.cell is not None:
            self.cell.append(value)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.cells.append("".join(self.cell))
            self.cell = None
        elif tag == "tr" and self.cells is not None:
            self.rows.append(self.cells)
            self.cells = None


class EvaluationReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def run_builder(self, data=None, *, name="results.json", extra=()):
        source = SAMPLE
        if data is not None:
            source = self.directory / name
            source.write_text(json.dumps(data), encoding="utf-8")
        output = self.directory / "report.html"
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SCRIPT), str(source), "--output", str(output), *extra],
            capture_output=True, text=True, cwd=self.directory,
        )
        return result, output

    def build(self, data=None, **kwargs):
        result, output = self.run_builder(data, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = output.read_text(encoding="utf-8")
        return html, Page(html)

    def test_sample_build_is_escaped_self_contained_and_reproducible(self):
        html, page = self.build()
        self.assertIn("sample data", html)
        self.assertIn("Sample data — not measured results.", html)
        attack = self.data["cases"][-1]["intent"]
        self.assertIn(escape(attack, quote=True), html)
        self.assertNotIn(attack, html)
        self.assertIn(attack, "".join(page.text))
        self.assertEqual(sum(tag == "svg" for tag, _ in page.tags), 3)
        self.assertEqual(sum(tag == "style" for tag, _ in page.tags), 1)
        self.assertNotIn("@import", html)
        self.assertNotIn("url(", html)
        self.assertIn(["sample-glimmer", "2", "1", "0", "1", "0", "12.00"], page.rows)
        self.assertIn(["sample-spark-open", "3", "0", "1", "0", "0", "4.50"], page.rows)
        self.assertIn(["sample-spark", "2", "1", "0", "0", "1", "4.00"], page.rows)
        self.assertTrue(any(row[-3:] == ["Missing", "Not evaluated", "N/A"] for row in page.rows))
        self.assertEqual(html, self.build()[0])

    def test_all_free_text_fields_escape_html_svg_quotes_and_ampersands(self):
        payload = '</title></text><script>alert("x")</script><svg onload="bad()"> & \'single\' "double"'
        data = copy.deepcopy(self.data)
        data["generated"] = payload + " generated"
        data["models"][0]["id"] = payload + " model"
        data["models"][0]["provider"] = payload + " provider"
        data["cases"][0]["id"] = payload + " case"
        data["cases"][0]["intent"] = payload + " intent"
        for row in data["results"]:
            if row["model"] == "sample-glimmer":
                row["model"] = data["models"][0]["id"]
            if row["case"] == "g01":
                row["case"] = data["cases"][0]["id"]
        html, page = self.build(data)
        for suffix in ("generated", "model", "provider", "case", "intent"):
            value = payload + " " + suffix
            self.assertIn(escape(value, quote=True), html)
            self.assertIn(value, "".join(page.text))
            self.assertNotIn(value, html)
        self.assertEqual(sum(tag == "svg" for tag, _ in page.tags), 3)

    def test_sample_labels_for_filename_and_explicit_flag(self):
        html, _ = self.build(self.data, name="sample-results.json")
        self.assertIn("Sample data — not measured results.", html)
        html, _ = self.build(self.data, extra=("--sample",))
        self.assertIn("Sample data — not measured results.", html)
        html, _ = self.build(self.data)
        self.assertNotIn("Sample data — not measured results.", html)

    def test_empty_and_error_only_results_have_no_median(self):
        data = copy.deepcopy(self.data)
        data["results"] = []
        _, page = self.build(data)
        self.assertIn(["sample-glimmer", "0", "0", "0", "0", "4", "N/A"], page.rows)
        data["results"] = [copy.deepcopy(self.data["results"][3])]
        _, page = self.build(data)
        self.assertIn(["sample-glimmer", "0", "0", "0", "1", "3", "N/A"], page.rows)
        data["models"] = []
        data["results"] = []
        html, _ = self.build(data)
        self.assertIn("No models supplied.", html)

    def test_invalid_data_is_rejected_without_replacing_output(self):
        variants = []
        for seconds in (-1, float("nan"), float("inf"), True, "12"):
            data = copy.deepcopy(self.data)
            data["results"][0]["seconds"] = seconds
            variants.append(data)
        for field in ("status", "verdict"):
            data = copy.deepcopy(self.data)
            data["results"][0][field] = "<script>bad()</script>"
            variants.append(data)
        for key in ("models", "cases", "results"):
            data = copy.deepcopy(self.data)
            data[key].append(copy.deepcopy(data[key][0]))
            variants.append(data)
        for field in ("case", "model"):
            data = copy.deepcopy(self.data)
            data["results"][0][field] = "not-declared"
            variants.append(data)
        data = copy.deepcopy(self.data)
        data["cases"][0]["category"] = "<svg onload=bad()>"
        variants.append(data)
        data = copy.deepcopy(self.data)
        data["results"][0]["status"] = "error"
        variants.append(data)
        data = copy.deepcopy(self.data)
        data["models"][0]["cloud"] = "false"
        variants.append(data)
        for index, data in enumerate(variants):
            with self.subTest(index=index):
                output = self.directory / "report.html"
                output.write_text("keep existing report", encoding="utf-8")
                result, _ = self.run_builder(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_text(encoding="utf-8"), "keep existing report")

    def test_input_cannot_be_overwritten(self):
        source = self.directory / "results.json"
        original = json.dumps(self.data)
        source.write_text(original, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(source), "--output", str(source)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()

