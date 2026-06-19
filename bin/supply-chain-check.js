#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { buildResponsePlan } = require("../src/response-plan");

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }

  const report = scanTarget(args.target);
  if (args.responsePlan) {
    report.responsePlan = buildResponsePlan(report);
  }

  let writtenReportPath = "";
  if (args.reportPath) {
    writtenReportPath = path.resolve(args.reportPath);
    fs.writeFileSync(writtenReportPath, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printHuman(report, writtenReportPath);
    if (args.responsePlan) {
      printResponsePlan(report.responsePlan);
    }
  }

  return report.risk === "likely-exposed" ? 2 : 0;
}

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    reportPath: "",
    responsePlan: false,
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--response-plan") {
      args.responsePlan = true;
    } else if (arg === "--report") {
      args.reportPath = argv[index + 1] || "";
      if (!args.reportPath) throw new Error("--report requires a file path");
      index += 1;
    } else if (arg.startsWith("--report=")) {
      args.reportPath = arg.slice("--report=".length);
      if (!args.reportPath) throw new Error("--report requires a file path");
    } else if (!arg.startsWith("-")) {
      args.target = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`supply-chain-check

Read-only dependency and source risk checker for pre-execution supply-chain review.

Usage:
  node bin/supply-chain-check.js [target] [--json] [--report report.json] [--response-plan]

Options:
  --json              print JSON report to stdout
  --report <path>     write JSON report to a specific path
  --response-plan     print text-only next references for matched findings;
                      this tool never executes cleanup

Exit codes:
  0  no known critical indicators found
  2  likely exposure indicators found
`);
}

function printHuman(report, writtenReportPath) {
  console.log("Supply Chain Check");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.summary.filesScanned} files, ${report.summary.packageManifestsScanned} package manifests, ${report.summary.lockfilesScanned} lockfiles`);
  console.log(`Findings: ${report.summary.findings}`);
  console.log("");

  printPlainLanguageSummary(report);

  if (report.findings.length > 0) {
    console.log("Technical findings:");
    for (const item of report.findings) {
      console.log(`[${item.severity}] ${item.type}`);
      console.log(`  ${item.path}`);
      console.log(`  ${item.message}`);
    }
    console.log("");
  }

  console.log("Guidance:");
  for (const item of report.guidance) {
    console.log(`- ${item}`);
  }

  if (writtenReportPath) {
    console.log("");
    console.log(`JSON report written: ${writtenReportPath}`);
  }
}

function printPlainLanguageSummary(report) {
  if (report.risk === "likely-exposed") {
    console.log("STOP");
    console.log("This project references known malicious dependency or source indicators.");
    console.log("Do not run package install, build, test, or dev-server commands here until reviewed.");
    console.log("If anything may have already executed, move to host incident response and use a clean machine for account work.");
    console.log("");
    return;
  }

  if (report.risk === "possible-exposure" || report.risk === "review-needed") {
    console.log("PAUSE");
    console.log("This project has suspicious or campaign-adjacent dependency signals.");
    console.log("Review the findings before running package installs or builds.");
    console.log("");
    return;
  }

  console.log("No known supply-chain indicators were found by this checker.");
  console.log("This does not prove the host is clean; it only covers the indicators this tool knows about.");
  console.log("");
}

function printResponsePlan(plan) {
  console.log("");
  console.log(plan.title);
  console.log(plan.boundary);
  console.log("");

  for (const item of plan.summary) {
    console.log(`- ${item}`);
  }

  if (plan.items.length > 0) {
    console.log("");
    console.log("Finding response:");
    for (const item of plan.items) {
      console.log(`[${item.severity}] ${item.type}`);
      console.log(`  Path: ${item.path}`);
      console.log(`  Found: ${item.finding}`);
      console.log("  Next:");
      for (const step of item.next) {
        console.log(`  - ${step}`);
      }
      console.log("  References:");
      for (const reference of item.references) {
        console.log(`  - ${reference}`);
      }
    }
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
