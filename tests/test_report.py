from __future__ import annotations

import json
import unittest
from pathlib import Path

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.reporting.markdown import MarkdownReportRenderer
from cloud_threat_modeler.reporting.sarif import SarifReportRenderer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_alb_ec2_rds_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_lambda_deploy_role_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_unconstrained_plan.json"
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_constrained_plan.json"
EXAMPLES_DIR = ROOT / "examples"


class MarkdownReportRendererTests(unittest.TestCase):
    def test_report_contains_summary_findings_and_limitations(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = MarkdownReportRenderer().render(result)

        self.assertIn("# Cloud Threat Model Report", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Discovered Trust Boundaries", report)
        self.assertIn("## Findings", report)
        self.assertIn("### High", report)
        self.assertIn("### Medium", report)
        self.assertIn("- Severity reasoning:", report)
        self.assertIn("- Evidence:", report)
        self.assertIn("Cross-account or broad role trust lacks narrowing conditions", report)
        self.assertIn("trust narrowing", report)
        self.assertIn("security group rules", report)
        self.assertIn("## Limitations / Unsupported Resources", report)
        self.assertIn("aws_cloudwatch_log_group.processor", report)

    def test_report_renders_unconstrained_trust_evidence(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH)
        report = MarkdownReportRenderer().render(result)

        self.assertIn("Cross-account or broad role trust lacks narrowing conditions", report)
        self.assertIn("supported narrowing conditions present: false", report)
        self.assertIn("supported narrowing condition keys: none", report)

    def test_report_renders_controls_observed_section(self) -> None:
        engine = CloudThreatModeler()
        safe_report = MarkdownReportRenderer().render(engine.analyze_plan(SAFE_FIXTURE_PATH))
        constrained_trust_report = MarkdownReportRenderer().render(
            engine.analyze_plan(CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH)
        )

        self.assertIn("## Controls Observed", safe_report)
        self.assertIn("S3 public access is reduced by a public access block", safe_report)
        self.assertIn("RDS instance is private and storage encrypted", safe_report)
        self.assertIn("## Controls Observed", constrained_trust_report)
        self.assertIn(
            "Cross-account or broad role trust is narrowed by assume-role conditions",
            constrained_trust_report,
        )
        self.assertIn(
            "supported narrowing condition keys: aws:SourceAccount, aws:SourceArn, sts:ExternalId",
            constrained_trust_report,
        )

    def test_checked_in_example_reports_match_renderer_output(self) -> None:
        engine = CloudThreatModeler()
        scenarios = {
            SAFE_FIXTURE_PATH: EXAMPLES_DIR / "safe_report.md",
            FIXTURE_PATH: EXAMPLES_DIR / "sample_report.md",
            NIGHTMARE_FIXTURE_PATH: EXAMPLES_DIR / "nightmare_report.md",
            ALB_EC2_RDS_FIXTURE_PATH: EXAMPLES_DIR / "alb_ec2_rds_report.md",
            LAMBDA_DEPLOY_ROLE_FIXTURE_PATH: EXAMPLES_DIR / "lambda_deploy_role_report.md",
        }

        for fixture_path, report_path in scenarios.items():
            with self.subTest(fixture=fixture_path.name):
                expected = engine.render_markdown_report(fixture_path)
                actual = report_path.read_text(encoding="utf-8")
                self.assertEqual(actual, expected)


class SarifReportRendererTests(unittest.TestCase):
    def test_sarif_report_contains_rules_results_and_finding_metadata(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = SarifReportRenderer().render(result)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("$schema", payload)
        self.assertEqual(len(payload["runs"]), 1)

        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "cloud-threat-modeler")
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertEqual(len(run["results"]), len(result.findings))

        database_result = next(
            sarif_result
            for sarif_result in run["results"]
            if sarif_result["ruleId"] == "aws-database-permissive-ingress"
        )
        self.assertEqual(database_result["level"], "error")
        self.assertEqual(database_result["message"]["text"], "Database is reachable from overly permissive sources")
        self.assertEqual(database_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], str(FIXTURE_PATH))
        self.assertEqual(database_result["properties"]["severity"], "high")
        self.assertTrue(database_result["properties"]["evidence"])
        self.assertEqual(database_result["properties"]["severity_reasoning"]["final_score"], 6)

        trust_result = next(
            sarif_result
            for sarif_result in run["results"]
            if sarif_result["ruleId"] == "aws-role-trust-missing-narrowing"
        )
        self.assertEqual(trust_result["level"], "warning")
        self.assertEqual(
            trust_result["message"]["text"],
            "Cross-account or broad role trust lacks narrowing conditions",
        )
        self.assertTrue(trust_result["properties"]["evidence"])

    def test_app_can_render_sarif_report(self) -> None:
        engine = CloudThreatModeler()
        report = engine.render_sarif_report(FIXTURE_PATH)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "cloud-threat-modeler")


if __name__ == "__main__":
    unittest.main()
