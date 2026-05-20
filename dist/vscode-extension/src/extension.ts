// Entry point for the VS Code extension.
//
// Flow on file save (or on the command palette command):
//   1. Spawn `leakferret scan FILE --format json --only FILE`
//   2. Get back a JSON array of candidates (verdict: "unknown")
//   3. For each candidate, ask the host LM (Copilot, Claude, whatever the
//      user has wired up via vscode.lm.selectChatModels) to classify
//      REAL / FIXTURE / UNKNOWN
//   4. Surface REAL findings as Error diagnostics, UNKNOWN as Warning,
//      FIXTURE not shown
//   5. Offer Quick Fix: "Replace with ENV.fetch" — runs `leakferret rewrite
//      --apply` for that specific finding
//
// The LM call uses the user's already-paid Copilot subscription (or
// Claude / OpenAI provider configured in VS Code). We never carry our own
// LLM API key.

import * as vscode from 'vscode';
import * as cp from 'child_process';

type Candidate = {
  path: string;
  line: number;
  column: number;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  match_redacted: string;
  context: string[];
  verdict?: 'real' | 'fixture' | 'unknown';
  reason?: string;
  confidence?: number;
};

const diagnostics = vscode.languages.createDiagnosticCollection('leakferret');

const CLASSIFY_SYSTEM_PROMPT = `
You're reviewing regex hits that may be hardcoded secrets in source code.
For each candidate you'll get: file path, pattern name, a redacted preview
of the matched value (first 4 + last 4 chars only), and a few lines of
surrounding context.

Classify each candidate as one of:
  REAL    — looks like a live secret that shipped in production source
  FIXTURE — looks like a test fixture, mock, stub, example, doc, or
            obvious dummy (EXAMPLE / xxxx / placeholder / CHANGEME)
  UNKNOWN — can't tell from this context alone

Bias toward FIXTURE on paths containing spec/, test/, tests/, fixtures/,
examples/, docs/, demo/, sample/, mock/, dummy/, or filenames like
.env.example / .env.sample.

Bias toward REAL on paths under app/, lib/, src/, config/ (except
config/credentials.yml.enc), cmd/, services/ with live provider structure.

Default to UNKNOWN on genuine ambiguity. Don't guess.

Output strict JSON only, no prose, no markdown fences:
[{"id":"0","verdict":"REAL|FIXTURE|UNKNOWN","reason":"...","confidence":0.0}]
`.trim();

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand('leakferret.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      await scanAndClassify(editor.document);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('leakferret.scanWorkspace', async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders) return;
      for (const folder of folders) {
        await scanAndClassifyWorkspace(folder.uri.fsPath);
      }
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const cfg = vscode.workspace.getConfiguration('leakferret');
      if (!cfg.get<boolean>('classifyOnSave', true)) return;
      await scanAndClassify(doc);
    }),
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new LeakferretCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );
}

export function deactivate() {
  diagnostics.dispose();
}

async function scanAndClassify(doc: vscode.TextDocument) {
  if (doc.uri.scheme !== 'file') return;
  const filePath = doc.uri.fsPath;
  const candidates = await runScanner(filePath, [filePath]);
  if (candidates.length === 0) {
    diagnostics.set(doc.uri, []);
    return;
  }

  const classified = await classifyWithHostLM(candidates);
  diagnostics.set(doc.uri, candidatesToDiagnostics(classified));
}

async function scanAndClassifyWorkspace(rootPath: string) {
  const candidates = await runScanner(rootPath, null);
  const classified = await classifyWithHostLM(candidates);

  const byPath = new Map<string, Candidate[]>();
  for (const c of classified) {
    const abs = `${rootPath}/${c.path}`;
    if (!byPath.has(abs)) byPath.set(abs, []);
    byPath.get(abs)!.push(c);
  }
  for (const [absPath, cs] of byPath) {
    diagnostics.set(vscode.Uri.file(absPath), candidatesToDiagnostics(cs));
  }
}

function runScanner(scanPath: string, only: string[] | null): Promise<Candidate[]> {
  return new Promise((resolve, reject) => {
    const cfg = vscode.workspace.getConfiguration('leakferret');
    const cli = cfg.get<string>('gemPath', 'leakferret');
    const args = ['scan', scanPath, '--format', 'json'];
    if (only && only.length > 0) {
      args.push('--only', ...only);
    }

    const proc = cp.spawn(cli, args, { shell: false });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (b) => (stdout += b.toString()));
    proc.stderr.on('data', (b) => (stderr += b.toString()));
    proc.on('error', reject);
    proc.on('close', (code) => {
      // The CLI exits 1 when there are REAL findings; that's still a successful run.
      if (code === 0 || code === 1) {
        try {
          resolve(stdout.trim() ? JSON.parse(stdout) : []);
        } catch (e) {
          reject(new Error(`leakferret scan: bad JSON: ${e}\nstderr: ${stderr}`));
        }
      } else {
        reject(new Error(`leakferret scan exited ${code}: ${stderr}`));
      }
    });
  });
}

async function classifyWithHostLM(candidates: Candidate[]): Promise<Candidate[]> {
  if (candidates.length === 0) return [];

  const cfg = vscode.workspace.getConfiguration('leakferret');
  const familyPref = cfg.get<string>('modelFamily', 'gpt-4o');

  // vscode.lm landed in 1.85+. If it's not present (older VS Code / no Copilot),
  // fall back to whatever the scan returned (verdict: 'unknown').
  if (!('lm' in vscode) || typeof (vscode as any).lm?.selectChatModels !== 'function') {
    return candidates;
  }

  let model;
  try {
    const models = await (vscode as any).lm.selectChatModels({ family: familyPref });
    model = models[0] || (await (vscode as any).lm.selectChatModels())[0];
  } catch {
    return candidates;
  }
  if (!model) return candidates;

  const userMsg = candidates
    .map((c, idx) =>
      [
        '---',
        `id: ${idx}`,
        `path: ${c.path}`,
        `pattern: ${c.pattern}`,
        `match: ${c.match_redacted}`,
        'context:',
        c.context.map((l) => `  ${l}`).join('\n'),
      ].join('\n'),
    )
    .join('\n\n');

  const messages = [
    (vscode as any).LanguageModelChatMessage.User(CLASSIFY_SYSTEM_PROMPT),
    (vscode as any).LanguageModelChatMessage.User(userMsg),
  ];

  try {
    const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);
    let text = '';
    for await (const chunk of response.text) {
      text += chunk;
    }
    const parsed = JSON.parse(text.trim().replace(/^```json\s*|\s*```$/g, ''));
    for (const v of parsed) {
      const idx = parseInt(v.id, 10);
      if (!candidates[idx]) continue;
      candidates[idx].verdict = String(v.verdict).toLowerCase() as Candidate['verdict'];
      candidates[idx].reason = v.reason;
      candidates[idx].confidence = v.confidence;
    }
  } catch (e) {
    // LM unreachable / refused / output not JSON. Fall back silently.
    console.warn('[leakferret] LM classification failed:', e);
  }

  return candidates;
}

function candidatesToDiagnostics(candidates: Candidate[]): vscode.Diagnostic[] {
  return candidates
    .filter((c) => c.verdict !== 'fixture')
    .map((c) => {
      const range = new vscode.Range(
        new vscode.Position(Math.max(c.line - 1, 0), Math.max(c.column - 1, 0)),
        new vscode.Position(Math.max(c.line - 1, 0), Math.max(c.column - 1, 0) + (c.match_redacted?.length ?? 16)),
      );
      const severity =
        c.verdict === 'real'
          ? vscode.DiagnosticSeverity.Error
          : vscode.DiagnosticSeverity.Warning;
      const reason = c.reason ? `\n${c.reason}` : '';
      const d = new vscode.Diagnostic(
        range,
        `[leakferret] ${c.pattern} (${c.severity}) — ${c.verdict?.toUpperCase()}${reason}`,
        severity,
      );
      d.source = 'leakferret';
      d.code = c.pattern;
      return d;
    });
}

class LeakferretCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== 'leakferret') continue;
      const fix = new vscode.CodeAction(
        'Replace with ENV.fetch (leakferret)',
        vscode.CodeActionKind.QuickFix,
      );
      fix.diagnostics = [diag];
      fix.command = {
        title: 'leakferret rewrite',
        command: 'leakferret.applyRewrite',
        arguments: [document.uri, diag.range],
      };
      actions.push(fix);
    }
    return actions;
  }
}
