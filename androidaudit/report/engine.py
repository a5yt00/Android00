from __future__ import annotations
from pathlib import Path
import jinja2

from androidaudit.findings import Finding

class ReportEngine:
    """Reporting engine utilizing findings and jinja templates."""
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.id, f.evidence, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _render(self, findings: list[Finding], template_name: str, package: str) -> str:
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"))
        template = env.get_template(template_name)
        
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] += 1
            
        sorted_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)
        
        return template.render(
            package=package,
            findings=sorted_findings,
            counts=counts,
            total=len(findings)
        )

    def generate_html(self, findings: list[Finding], package: str, out_filename: str) -> None:
        uniq = self.deduplicate(findings)
        html = self._render(uniq, "report.html.j2", package)
        (self.output_dir / out_filename).write_text(html, encoding="utf-8")
        
    def generate_md(self, findings: list[Finding], package: str, out_filename: str) -> None:
        uniq = self.deduplicate(findings)
        md = self._render(uniq, "summary.md.j2", package)
        (self.output_dir / out_filename).write_text(md, encoding="utf-8")
