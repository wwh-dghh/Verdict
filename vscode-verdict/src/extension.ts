import * as vscode from "vscode";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

// VS Code diagnostic collection for verdict findings
let diagnosticCollection: vscode.DiagnosticCollection;

interface VerdictFinding {
  category: string;
  severity: string;
  code: string;
  message: string;
  file: string;
  line: number | null;
  column: number | null;
  suggestion: string | null;
  ai_explanation: string | null;
}

interface VerdictResult {
  stages_completed: string[];
  results: Array<{
    path: string;
    language: string | null;
    findings: VerdictFinding[];
    scores: {
      security: number;
      code_quality: number;
      performance: number;
      test_coverage: number;
      ai_risk: number;
      overall: number;
    } | null;
    duration_ms: number;
  }>;
  total_findings: number;
  failed_thresholds: string[];
  exit_code: number;
}

function getVerdictPath(): string {
  return (
    vscode.workspace.getConfiguration("verdict").get<string>("path") ||
    "verdict"
  );
}

function getSeverity(vscode_severity: string): vscode.DiagnosticSeverity {
  switch (vscode_severity.toLowerCase()) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "info":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

async function runVerdictCheck(
  targets: string[],
  diffMode: boolean = false
): Promise<VerdictResult | null> {
  const verdictPath = getVerdictPath();
  const args = ["check", "--format", "json"];
  if (diffMode) {
    args.push("--diff");
  }
  args.push(...targets);

  try {
    const { stdout } = await execFileAsync(verdictPath, args, {
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return JSON.parse(stdout) as VerdictResult;
  } catch (err: any) {
    // verdict exits with code 1 when findings exist
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout) as VerdictResult;
      } catch {
        // parse failed
      }
    }
    vscode.window.showErrorMessage(`Verdict check failed: ${err.message}`);
    return null;
  }
}

function updateDiagnostics(result: VerdictResult | null) {
  diagnosticCollection.clear();
  if (!result) return;

  for (const fileResult of result.results) {
    const uri = vscode.Uri.file(fileResult.path);
    const diagnostics: vscode.Diagnostic[] = [];

    for (const finding of fileResult.findings) {
      const line = Math.max(0, (finding.line || 1) - 1);
      const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.code}] ${finding.message}`,
        getSeverity(finding.severity)
      );

      diagnostic.source = "verdict";
      diagnostic.code = finding.code;

      if (finding.suggestion) {
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(uri, range),
            `Suggestion: ${finding.suggestion}`
          ),
        ];
      }

      diagnostics.push(diagnostic);
    }

    diagnosticCollection.set(uri, diagnostics);
  }
}

async function checkWorkspace() {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    vscode.window.showWarningMessage("No workspace folder open");
    return;
  }

  vscode.window.setStatusBarMessage(
    "$(sync~spin) Verdict: checking...",
    (async () => {
      const targets = workspaceFolders.map((f) => f.uri.fsPath);
      const result = await runVerdictCheck(targets);
      updateDiagnostics(result);

      if (result) {
        const msg =
          result.total_findings === 0
            ? "✓ No issues found"
            : `✗ ${result.total_findings} finding(s)`;
        vscode.window.setStatusBarMessage(`Verdict: ${msg}`, 5000);
      }
    })() as any
  );
}

async function checkCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("No active editor");
    return;
  }

  const filePath = editor.document.fileName;
  const result = await runVerdictCheck([filePath]);
  updateDiagnostics(result);

  if (result) {
    const findings = result.results[0]?.findings.length || 0;
    vscode.window.showInformationMessage(
      findings === 0
        ? "Verdict: No issues found"
        : `Verdict: ${findings} finding(s) in current file`
    );
  }
}

function showRules() {
  const rules = [
    { code: "SEC001", name: "SQL Injection", severity: "Error" },
    { code: "SEC002", name: "XSS", severity: "Error/Warning" },
    { code: "SEC003", name: "Hardcoded Secrets", severity: "Error" },
    { code: "SEC004", name: "Weak Crypto", severity: "Warning" },
    { code: "SEC005", name: "Debug Log Leak", severity: "Warning" },
    { code: "SEC006", name: "Unsafe eval()", severity: "Error" },
    { code: "SEC007", name: "Command Injection", severity: "Error" },
  ];

  const items = rules.map((r) => ({
    label: `${r.code} — ${r.name}`,
    description: r.severity,
  }));

  vscode.window.showQuickPick(items, {
    placeHolder: "Verdict Security Rules",
  });
}

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("verdict");
  context.subscriptions.push(diagnosticCollection);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("verdict.check", checkWorkspace)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("verdict.checkFile", checkCurrentFile)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("verdict.rules", showRules)
  );

  // Auto-check on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration("verdict");
      if (!config.get<boolean>("enableOnSave")) return;

      const supportedLanguages = [
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
      ];
      if (supportedLanguages.includes(document.languageId)) {
        runVerdictCheck([document.fileName]).then(updateDiagnostics);
      }
    })
  );

  // Initial check on activation
  const config = vscode.workspace.getConfiguration("verdict");
  if (config.get<boolean>("enableOnSave")) {
    checkWorkspace();
  }

  console.log("Verdict extension activated");
}

export function deactivate() {
  diagnosticCollection?.clear();
}
