// Post step: summarise g0efilter decisions from the container logs into the
// job summary. Dependency-free on purpose: no npm install or dist build step.
"use strict";

const { execSync } = require("node:child_process");
const fs = require("node:fs");

function containerLogs() {
  try {
    return execSync("docker logs g0efilter 2>&1", {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return "";
  }
}

function collectDecisions(raw) {
  const decisions = new Map();
  let allowed = 0;

  for (const line of raw.split("\n")) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }

    if (entry.action === "ALLOWED") {
      allowed++;
      continue;
    }
    if (entry.action !== "BLOCKED" && entry.action !== "AUDIT") {
      continue;
    }

    const host = entry.https || entry.host || entry.qname || entry.identifier || "";
    const dest = entry.dst || entry.destination_ip || "";
    const key = [entry.action, entry.component, host, dest].join("|");
    const seen = decisions.get(key);

    if (seen) {
      seen.count++;
    } else {
      decisions.set(key, {
        action: entry.action,
        component: entry.component || "",
        host,
        dest,
        count: 1,
      });
    }
  }

  return { decisions: [...decisions.values()], allowed };
}

function buildSummary(raw) {
  let md = "## g0efilter egress report\n\n";

  if (!raw.trim()) {
    return md + "No g0efilter logs found - the filter may have failed to start.\n";
  }

  const { decisions, allowed } = collectDecisions(raw);
  if (decisions.length === 0) {
    return md + `No blocked or audited connections (${allowed} allowed decisions logged).\n`;
  }

  const policy = process.env["INPUT_EGRESS-POLICY"] || "block";
  md += `Egress policy: \`${policy}\` - ${allowed} allowed decisions logged.\n\n`;
  md += "| Action | Component | Domain / Host | Destination | Count |\n";
  md += "|---|---|---|---|---|\n";

  decisions.sort((a, b) => b.count - a.count);
  for (const d of decisions) {
    const icon = d.action === "BLOCKED" ? "🚫 BLOCKED" : "⚠️ AUDIT";
    md += `| ${icon} | ${d.component} | ${d.host} | ${d.dest} | ${d.count} |\n`;
  }

  return md;
}

const summary = buildSummary(containerLogs());
if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
} else {
  console.log(summary);
}
