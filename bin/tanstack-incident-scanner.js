#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }

  const report = scanTarget(args.target);
  let writtenReportPath = "";
  if (args.reportPath) {
    writtenReportPath = path.resolve(args.reportPath);
    fs.writeFileSync(writtenReportPath, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printHuman(report, writtenReportPath);
  }

  return report.risk === "likely-exposed" ? 2 : 0;
}

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    reportPath: "",
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
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
  console.log(`tanstack-incident-scanner

Read-only exposure scanner for the May 2026 TanStack npm supply-chain incident.

Usage:
  node bin/tanstack-incident-scanner.js [target] [--json] [--report report.json]

Options:
  --json              print JSON report to stdout
  --report <path>     write JSON report to a specific path

Exit codes:
  0  no known critical indicators found
  2  likely exposure indicators found
`);
}

function printHuman(report, writtenReportPath) {
  console.log("TanStack Incident Scanner");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.summary.filesScanned} files, ${report.summary.packageManifestsScanned} package manifests, ${report.summary.lockfilesScanned} lockfiles`);
  console.log(`Findings: ${report.summary.findings}`);
  console.log("");

  if (report.findings.length > 0) {
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

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
