import React, { useState, useMemo, useRef } from "react";
import {
  ShieldAlert, Bug, Gauge, Search, Upload, FileCode2, ChevronRight, X,
  Sparkles, Loader2, CheckCircle2, AlertTriangle, AlertCircle, Info,
  Play, FolderOpen, Layers, ClipboardList, HelpCircle
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell
} from "recharts";

/* ============================================================
   STATIC ANALYSIS ENGINE
   Heuristic, regex + structure based. No fabricated findings —
   every issue below is produced by a real check against the
   actual submitted code.
   ============================================================ */

const SEVERITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_WEIGHT = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
const SEVERITY_COLOR = {
  CRITICAL: { bg: "bg-red-100", text: "text-red-800", dot: "bg-red-600", ring: "ring-red-200" },
  HIGH: { bg: "bg-orange-100", text: "text-orange-800", dot: "bg-orange-500", ring: "ring-orange-200" },
  MEDIUM: { bg: "bg-amber-100", text: "text-amber-800", dot: "bg-amber-500", ring: "ring-amber-200" },
  LOW: { bg: "bg-blue-100", text: "text-blue-800", dot: "bg-blue-500", ring: "ring-blue-200" },
  INFO: { bg: "bg-slate-100", text: "text-slate-600", dot: "bg-slate-400", ring: "ring-slate-200" },
};

function detectLanguage(filename) {
  const ext = filename.split(".").pop().toLowerCase();
  if (ext === "py") return "python";
  if (ext === "ts" || ext === "tsx") return "typescript";
  if (ext === "js" || ext === "jsx") return "javascript";
  return "unknown";
}

// Line-based rules. Each: {id, langs, re, category, severity, title, explain, fix}
const LINE_RULES = [
  {
    id: "hardcoded_secret", langs: ["python", "javascript", "typescript"],
    re: /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*["'][^"'\s]{4,}["']/i,
    category: "security", severity: "HIGH", title: "Hardcoded credential",
    explain: "A credential-like value is embedded directly in source code, where it can leak through version control, logs, or decompilation.",
    fix: "Load secrets from environment variables or a secrets manager (e.g. AWS Secrets Manager, Vault), never from source.",
  },
  {
    id: "sql_fstring", langs: ["python"],
    re: /f["'].{0,120}\b(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}\{[^}]+\}/i,
    category: "security", severity: "CRITICAL", title: "SQL query built with an f-string",
    explain: "User-influenced values appear to be interpolated directly into a SQL string, which can allow SQL injection if any part of the interpolated data is attacker-controlled.",
    fix: "Use parameterized queries (e.g. cursor.execute(query, params)) instead of string interpolation.",
  },
  {
    id: "sql_concat", langs: ["javascript", "typescript"],
    re: /(SELECT|INSERT|UPDATE|DELETE)\b[^;"'`]*["'`]\s*\+\s*\w/i,
    category: "security", severity: "HIGH", title: "SQL query built via string concatenation",
    explain: "A SQL statement is assembled by concatenating strings and variables, which is a classic SQL-injection vector if any concatenated value comes from user input.",
    fix: "Use a parameterized query / prepared statement API instead of concatenation.",
  },
  {
    id: "eval_usage", langs: ["python", "javascript", "typescript"],
    re: /\beval\s*\(/,
    category: "security", severity: "HIGH", title: "Use of eval()",
    explain: "eval() executes arbitrary code from a string at runtime. If any part of that string is influenced by user input, it can lead to remote code execution.",
    fix: "Replace eval() with a safe alternative: JSON.parse for data, an explicit dispatch table for logic, or ast.literal_eval in Python for literals only.",
  },
  {
    id: "exec_usage", langs: ["python"],
    re: /\bexec\s*\(/,
    category: "security", severity: "HIGH", title: "Use of exec()",
    explain: "exec() runs arbitrary Python code from a string, which is dangerous if the string can be influenced by external input.",
    fix: "Avoid exec(); use explicit function calls or a restricted, well-defined interface instead.",
  },
  {
    id: "shell_true", langs: ["python"],
    re: /subprocess\.(Popen|call|run|check_output|check_call)\([^)]*shell\s*=\s*True/,
    category: "security", severity: "CRITICAL", title: "subprocess call with shell=True",
    explain: "shell=True invokes a system shell to interpret the command string, so any unsanitized input concatenated into it can enable shell/command injection.",
    fix: "Pass the command as a list of arguments and drop shell=True, e.g. subprocess.run(['ls', path]).",
  },
  {
    id: "os_system", langs: ["python"],
    re: /\bos\.system\s*\(/,
    category: "security", severity: "HIGH", title: "os.system() call",
    explain: "os.system() runs a command through the shell. If any part of the command string includes untrusted input, it is vulnerable to command injection.",
    fix: "Use subprocess.run([...]) with a list of arguments instead of os.system().",
  },
  {
    id: "pickle_loads", langs: ["python"],
    re: /pickle\.loads?\s*\(/,
    category: "security", severity: "HIGH", title: "Unsafe deserialization with pickle",
    explain: "pickle.load/loads can execute arbitrary code while deserializing a crafted payload. Deserializing untrusted data is a known remote-code-execution vector.",
    fix: "Avoid unpickling untrusted data. Use a safe serialization format like JSON, or cryptographically sign pickled payloads.",
  },
  {
    id: "yaml_unsafe_load", langs: ["python"],
    re: /yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)/,
    category: "security", severity: "MEDIUM", title: "yaml.load without SafeLoader",
    explain: "yaml.load() without an explicit safe loader can construct arbitrary Python objects from the YAML document, which can lead to code execution on untrusted input.",
    fix: "Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
  },
  {
    id: "weak_hash", langs: ["python", "javascript", "typescript"],
    re: /(hashlib\.md5|hashlib\.sha1|createHash\(\s*["'](md5|sha1)["'])/i,
    category: "security", severity: "MEDIUM", title: "Weak hashing algorithm",
    explain: "MD5 and SHA-1 are cryptographically broken for security-sensitive uses (password hashing, integrity checks against a motivated attacker).",
    fix: "Use bcrypt/argon2/scrypt for passwords, or SHA-256+ for integrity checks.",
  },
  {
    id: "inner_html", langs: ["javascript", "typescript"],
    re: /\.innerHTML\s*=\s*(?!["'`]\s*["'`])/,
    category: "security", severity: "MEDIUM", title: "Direct innerHTML assignment",
    explain: "Assigning dynamic content to innerHTML can enable cross-site scripting (XSS) if the value includes unsanitized user input.",
    fix: "Use textContent for plain text, or sanitize HTML with a library like DOMPurify before assignment.",
  },
  {
    id: "dangerously_set_html", langs: ["javascript", "typescript"],
    re: /dangerouslySetInnerHTML/,
    category: "security", severity: "MEDIUM", title: "dangerouslySetInnerHTML usage",
    explain: "This React API bypasses XSS protections. If the HTML source includes any unsanitized user input, it's an XSS vector.",
    fix: "Sanitize the HTML with DOMPurify before passing it, or avoid raw HTML injection entirely.",
  },
  {
    id: "bare_except", langs: ["python"],
    re: /^\s*except\s*:\s*$/,
    category: "quality", severity: "MEDIUM", title: "Bare except clause",
    explain: "A bare except: catches every exception, including SystemExit and KeyboardInterrupt, which hides real bugs and makes failures silent.",
    fix: "Catch specific exception types, e.g. except (ValueError, KeyError):",
  },
  {
    id: "empty_catch", langs: ["javascript", "typescript"],
    re: /catch\s*\([^)]*\)\s*\{\s*\}/,
    category: "quality", severity: "MEDIUM", title: "Empty catch block",
    explain: "Errors are being silently swallowed with no logging or handling, which makes failures invisible and hard to diagnose in production.",
    fix: "At minimum log the error; ideally handle it or re-throw with added context.",
  },
  {
    id: "console_log", langs: ["javascript", "typescript"],
    re: /console\.(log|debug)\(/,
    category: "quality", severity: "LOW", title: "Leftover console statement",
    explain: "Debug console statements left in shipped code add noise and can leak internal details to the browser console.",
    fix: "Remove debug logging or replace with a proper logger that respects log levels/environment.",
  },
  {
    id: "var_usage", langs: ["javascript", "typescript"],
    re: /^\s*var\s+[A-Za-z_$]/,
    category: "quality", severity: "LOW", title: "Use of var",
    explain: "var is function-scoped and hoisted, which causes subtle bugs around scoping and re-declaration that let/const avoid.",
    fix: "Use const by default, or let when reassignment is needed.",
  },
  {
    id: "todo_marker", langs: ["python", "javascript", "typescript"],
    re: /\b(TODO|FIXME|HACK)\b/,
    category: "maintainability", severity: "INFO", title: "TODO / FIXME marker",
    explain: "An unresolved TODO or FIXME marker indicates known incomplete or compromised work.",
    fix: "Track it in an issue tracker and resolve, or remove if stale.",
  },
];

// naive line-window duplicate detector (5-line windows, same file)
function findDuplicateBlocks(file) {
  const lines = file.content.split("\n");
  const WIN = 5;
  const seen = new Map();
  const issues = [];
  const flaggedStarts = new Set();
  for (let i = 0; i + WIN <= lines.length; i++) {
    const block = lines.slice(i, i + WIN).map((l) => l.trim()).join("\n");
    if (block.replace(/\s/g, "").length < 40) continue; // skip trivial/blank windows
    if (seen.has(block)) {
      const firstLine = seen.get(block);
      if (!flaggedStarts.has(i)) {
        flaggedStarts.add(i);
        issues.push({
          category: "maintainability", severity: "MEDIUM",
          title: "Duplicated code block",
          line: i + 1,
          explain: `This ${WIN}-line block closely repeats code first seen at line ${firstLine + 1}.`,
          fix: "Extract the shared logic into a function and call it from both locations.",
          snippet: lines.slice(i, i + WIN).join("\n"),
        });
      }
    } else {
      seen.set(block, i);
    }
  }
  return issues;
}

// extract top-level function ranges + a rough cyclomatic complexity count
function extractFunctions(content, language) {
  const lines = content.split("\n");
  const fns = [];
  if (language === "python") {
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^(\s*)def\s+(\w+)\s*\(/);
      if (!m) continue;
      const indent = m[1].length;
      const name = m[2];
      let end = i;
      for (let j = i + 1; j < lines.length; j++) {
        if (lines[j].trim() === "") { end = j; continue; }
        const lIndent = lines[j].match(/^(\s*)/)[1].length;
        if (lIndent <= indent) break;
        end = j;
      }
      fns.push({ name, start: i, end });
    }
  } else {
    const fnStart = /(function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*(async\s*)?\([^)]*\)\s*=>|(\w+)\s*\([^)]*\)\s*\{)/;
    for (let i = 0; i < lines.length; i++) {
      if (!fnStart.test(lines[i])) continue;
      const nameMatch = lines[i].match(fnStart);
      const name = nameMatch[2] || nameMatch[3] || nameMatch[5] || "anonymous";
      let braceIdx = lines[i].indexOf("{");
      let depth = 0, started = false, end = i;
      for (let j = i; j < lines.length; j++) {
        const scanStart = j === i ? (braceIdx >= 0 ? braceIdx : 0) : 0;
        for (let k = scanStart; k < lines[j].length; k++) {
          if (lines[j][k] === "{") { depth++; started = true; }
          if (lines[j][k] === "}") depth--;
        }
        end = j;
        if (started && depth <= 0) break;
        if (j - i > 400) break; // safety valve
      }
      if (started) fns.push({ name, start: i, end });
    }
  }
  return fns.map((fn) => {
    const body = lines.slice(fn.start, fn.end + 1).join("\n");
    const branchHits = (body.match(/\b(if|elif|else if|for|while|case|catch|except)\b|&&|\|\|/g) || []).length;
    const complexity = 1 + branchHits;
    const length = fn.end - fn.start + 1;
    return { ...fn, length, complexity };
  });
}

function findUnusedVariables(content, language) {
  const lines = content.split("\n");
  const issues = [];
  const declRe = language === "python"
    ? /^\s*([A-Za-z_]\w*)\s*=\s*(?!=)/
    : /\b(?:const|let)\s+([A-Za-z_$]\w*)\s*=/;
  const skip = new Set(["_", "self", "this", "i", "j", "k"]);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(declRe);
    if (!m) continue;
    const name = m[1];
    if (skip.has(name) || name.length <= 1) continue;
    const usesElsewhere = lines.some((l, idx) => idx !== i && new RegExp(`\\b${name}\\b`).test(l));
    if (!usesElsewhere) {
      issues.push({
        category: "maintainability", severity: "LOW", title: `Unused variable "${name}"`,
        line: i + 1,
        explain: `"${name}" is assigned but never referenced again in this file.`,
        fix: "Remove the unused variable, or use it — if it's intentional (e.g. destructuring), prefix with an underscore.",
        snippet: lines[i],
      });
    }
  }
  return issues;
}

function analyzeFile(file) {
  const language = detectLanguage(file.name);
  const lines = file.content.split("\n");
  const issues = [];

  lines.forEach((line, idx) => {
    LINE_RULES.forEach((rule) => {
      if (!rule.langs.includes(language)) return;
      if (rule.re.test(line)) {
        issues.push({
          category: rule.category, severity: rule.severity, title: rule.title,
          line: idx + 1, explain: rule.explain, fix: rule.fix, snippet: line.trim().slice(0, 200),
          ruleId: rule.id,
        });
      }
    });
  });

  findDuplicateBlocks(file).forEach((i) => issues.push(i));
  findUnusedVariables(file.content, language).forEach((i) => issues.push(i));

  const fns = extractFunctions(file.content, language);
  fns.forEach((fn) => {
    if (fn.length > 80) {
      issues.push({
        category: "complexity", severity: "HIGH", title: `Long function "${fn.name}" (${fn.length} lines)`,
        line: fn.start + 1,
        explain: `"${fn.name}" spans ${fn.length} lines, which makes it hard to read, test, and reason about in one pass.`,
        fix: "Split into smaller, single-purpose functions.",
        snippet: lines[fn.start].trim(),
      });
    } else if (fn.length > 50) {
      issues.push({
        category: "complexity", severity: "MEDIUM", title: `Long function "${fn.name}" (${fn.length} lines)`,
        line: fn.start + 1,
        explain: `"${fn.name}" spans ${fn.length} lines, above the ~50-line readability guideline.`,
        fix: "Consider extracting helper functions for distinct sub-tasks.",
        snippet: lines[fn.start].trim(),
      });
    }
    if (fn.complexity > 15) {
      issues.push({
        category: "complexity", severity: "HIGH", title: `High cyclomatic complexity in "${fn.name}" (~${fn.complexity})`,
        line: fn.start + 1,
        explain: `"${fn.name}" has an estimated cyclomatic complexity of ${fn.complexity} branch points, making it hard to test exhaustively.`,
        fix: "Reduce branching: extract conditions into named helper functions, use early returns, or a lookup table.",
        snippet: lines[fn.start].trim(),
      });
    } else if (fn.complexity > 10) {
      issues.push({
        category: "complexity", severity: "MEDIUM", title: `Elevated complexity in "${fn.name}" (~${fn.complexity})`,
        line: fn.start + 1,
        explain: `"${fn.name}" has an estimated cyclomatic complexity of ${fn.complexity}, above the ~10 guideline.`,
        fix: "Look for branches that can be simplified or extracted.",
        snippet: lines[fn.start].trim(),
      });
    }
  });

  return issues.map((issue, i) => ({
    id: `${file.name}:${issue.line || 0}:${issue.ruleId || issue.title}:${i}`,
    file: file.name,
    language,
    ...issue,
  }));
}

/* ---- scoring ----
   Security score      = 100 - sum(weight) over security issues
   Code Quality score   = 100 - 0.6 * sum(weight) over quality issues
   Maintainability score= 100 - 0.5 * sum(weight) over maintainability issues
   Complexity score     = 100 - 0.5 * sum(weight) over complexity issues
   Overall = average of the four, all floored at 0.
*/
function computeScores(issues) {
  const sumWeight = (cat, mult = 1) =>
    issues.filter((i) => i.category === cat).reduce((acc, i) => acc + SEVERITY_WEIGHT[i.severity] * mult, 0);
  const security = Math.max(0, Math.round(100 - sumWeight("security", 1)));
  const quality = Math.max(0, Math.round(100 - sumWeight("quality", 0.6)));
  const maintainability = Math.max(0, Math.round(100 - sumWeight("maintainability", 0.5)));
  const complexity = Math.max(0, Math.round(100 - sumWeight("complexity", 0.5)));
  const overall = Math.round((security + quality + maintainability + complexity) / 4);
  return { security, quality, maintainability, complexity, overall };
}

/* ============================================================
   SAMPLE STARTER PROJECT
   ============================================================ */
const SAMPLE_FILES = [
  {
    name: "auth.py",
    content: `import subprocess
import pickle
import hashlib

DB_PASSWORD = "sup3r_secret_pw_123"

def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = run_query(query)
    return result

def run_query(query):
    try:
        return db.execute(query)
    except:
        return None

def load_session(raw_bytes):
    session = pickle.loads(raw_bytes)
    return session

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def backup_database(path):
    subprocess.call("cp " + path + " /backups/", shell=True)

def process_request(req):
    # TODO: this whole function needs a rewrite, it grew out of control
    user = req.get("user")
    action = req.get("action")
    if user is None:
        return "no user"
    if action == "create":
        if req.get("payload") is None:
            return "no payload"
        else:
            if len(req.get("payload")) > 0:
                for item in req.get("payload"):
                    if item.get("type") == "a":
                        for sub in item.get("children", []):
                            if sub.get("valid"):
                                if sub.get("owner") == user:
                                    process_item(sub)
                                else:
                                    if user == "admin":
                                        process_item(sub)
                                    else:
                                        continue
                            else:
                                continue
                    elif item.get("type") == "b":
                        process_item(item)
                    else:
                        continue
            else:
                return "empty payload"
    elif action == "delete":
        delete_item(req.get("id"))
    elif action == "update":
        update_item(req.get("id"), req.get("payload"))
    else:
        return "unknown action"
    return "ok"

def process_item(item):
    pass

def delete_item(item_id):
    pass

def update_item(item_id, payload):
    pass
`,
  },
  {
    name: "dashboard.js",
    content: `function renderUserCard(user) {
  var el = document.getElementById("card");
  el.innerHTML = "<h3>" + user.name + "</h3><p>" + user.bio + "</p>";
  console.log("rendered card for", user.name);
}

function fetchAndRender(userId) {
  fetch("/api/users/" + userId)
    .then((res) => res.json())
    .then((user) => {
      renderUserCard(user);
    })
    .catch((err) => {});
}

function computeStats(events) {
  var total = 0;
  var flagged = 0;
  for (var i = 0; i < events.length; i++) {
    total = total + 1;
    if (events[i].type === "error") {
      flagged = flagged + 1;
    }
  }
  var unusedRatio = flagged / total;
  return total;
}

function runReport(rows) {
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var total = 0;
    var flagged = 0;
    for (var j = 0; j < rows.length; j++) {
      total = total + 1;
      if (rows[j].type === "error") {
        flagged = flagged + 1;
      }
    }
    out.push(total);
  }
  return out;
}
`,
  },
];

/* ============================================================
   UI HELPERS
   ============================================================ */
function ScoreRing({ label, value, icon: Icon }) {
  const color = value >= 85 ? "#0f6e56" : value >= 60 ? "#c98500" : "#b3261e";
  const circumference = 2 * Math.PI * 34;
  const offset = circumference * (1 - value / 100);
  return (
    <div className="flex flex-col items-center gap-2 bg-white rounded-xl border border-slate-200 px-4 py-5">
      <div className="relative w-20 h-20">
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="34" fill="none" stroke="#e5e7eb" strokeWidth="7" />
          <circle
            cx="40" cy="40" r="34" fill="none" stroke={color} strokeWidth="7"
            strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
            transform="rotate(-90 40 40)"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-lg font-semibold text-slate-800">{value}</span>
        </div>
      </div>
      <div className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
        <Icon size={13} /> {label}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const c = SEVERITY_COLOR[severity];
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full ${c.bg} ${c.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {severity}
    </span>
  );
}

function CategoryTag({ category }) {
  const labels = {
    security: "Security", quality: "Quality", maintainability: "Maintainability", complexity: "Complexity",
  };
  return <span className="text-[11px] font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">{labels[category] || category}</span>;
}

/* ============================================================
   MAIN APP
   ============================================================ */
export default function CodeReviewPlatform() {
  const [files, setFiles] = useState(SAMPLE_FILES);
  const [analyzed, setAnalyzed] = useState(false);
  const [issues, setIssues] = useState([]);
  const [tab, setTab] = useState("upload");
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [pasteText, setPasteText] = useState("");
  const [pasteFilename, setPasteFilename] = useState("snippet.py");
  const [aiExplain, setAiExplain] = useState({}); // issueId -> {loading, text}
  const [aiReview, setAiReview] = useState({ loading: false, text: "" });
  const fileInputRef = useRef(null);

  const runAnalysis = () => {
    const allIssues = files.flatMap((f) => analyzeFile(f));
    setIssues(allIssues);
    setAnalyzed(true);
    setTab("dashboard");
  };

  const handleFileUpload = (e) => {
    const uploaded = Array.from(e.target.files || []);
    if (!uploaded.length) return;
    Promise.all(
      uploaded.map(
        (f) =>
          new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = () => resolve({ name: f.name, content: String(reader.result) });
            reader.readAsText(f);
          })
      )
    ).then((newFiles) => {
      setFiles((prev) => [...prev, ...newFiles]);
      setAnalyzed(false);
    });
  };

  const addPastedSnippet = () => {
    if (!pasteText.trim()) return;
    setFiles((prev) => [...prev, { name: pasteFilename || "snippet.py", content: pasteText }]);
    setPasteText("");
    setAnalyzed(false);
  };

  const removeFile = (name) => {
    setFiles((prev) => prev.filter((f) => f.name !== name));
    setAnalyzed(false);
  };

  const scores = useMemo(() => computeScores(issues), [issues]);
  const totalLines = useMemo(() => files.reduce((a, f) => a + f.content.split("\n").length, 0), [files]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    issues.forEach((i) => counts[i.severity]++);
    return counts;
  }, [issues]);

  const chartData = SEVERITY.map((s) => ({ name: s, count: severityCounts[s] }));

  const filteredIssues = useMemo(() => {
    return issues
      .filter((i) => severityFilter === "ALL" || i.severity === severityFilter)
      .filter((i) => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          i.title.toLowerCase().includes(q) ||
          i.explain.toLowerCase().includes(q) ||
          i.category.toLowerCase().includes(q) ||
          i.file.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
  }, [issues, severityFilter, searchQuery]);

  async function callClaude(prompt) {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 1000,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await response.json();
    const text = (data.content || []).map((b) => b.text || "").join("\n");
    return text;
  }

  async function explainIssue(issue) {
    setAiExplain((prev) => ({ ...prev, [issue.id]: { loading: true, text: "" } }));
    try {
      const file = files.find((f) => f.name === issue.file);
      const lines = file ? file.content.split("\n") : [];
      const start = Math.max(0, (issue.line || 1) - 6);
      const end = Math.min(lines.length, (issue.line || 1) + 5);
      const context = lines.slice(start, end).join("\n");
      const prompt = `You are a senior code reviewer. A static analyzer flagged this issue in ${issue.file} around line ${issue.line}:

Issue: ${issue.title}
Category: ${issue.category}
Severity: ${issue.severity}

Code context:
\`\`\`
${context}
\`\`\`

In under 120 words, explain specifically (referencing the actual code shown) why this matters and give a concrete fix. Do not restate generic advice unrelated to this exact code.`;
      const text = await callClaude(prompt);
      setAiExplain((prev) => ({ ...prev, [issue.id]: { loading: false, text } }));
    } catch (err) {
      setAiExplain((prev) => ({ ...prev, [issue.id]: { loading: false, text: "Couldn't reach the AI service. Please try again." } }));
    }
  }

  async function generateAiReview() {
    setAiReview({ loading: true, text: "" });
    try {
      const combined = files.map((f) => `--- ${f.name} ---\n${f.content}`).join("\n\n").slice(0, 12000);
      const prompt = `You are an expert code reviewer. Review the following codebase across architecture, readability, maintainability, error handling, performance, and security. Be specific and cite file names / function names from the code. Structure your answer with a short heading per category, 2-4 sentences each. End with the top 3 priority fixes as a numbered list.

${combined}`;
      const text = await callClaude(prompt);
      setAiReview({ loading: false, text });
    } catch (err) {
      setAiReview({ loading: false, text: "Couldn't reach the AI service. Please try again." });
    }
  }

  const NavItem = ({ id, icon: Icon, label }) => (
    <button
      onClick={() => setTab(id)}
      className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors ${
        tab === id ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-100"
      }`}
    >
      <Icon size={15} /> {label}
    </button>
  );

  return (
    <div className="w-full min-h-[600px] bg-slate-50 text-slate-800 font-sans">
      <div className="max-w-5xl mx-auto px-5 py-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center">
              <FileCode2 size={18} className="text-white" />
            </div>
            <div>
              <h1 className="text-base font-semibold leading-tight">Sentry Review</h1>
              <p className="text-xs text-slate-500 leading-tight">AI-powered static analysis for Python, JavaScript &amp; TypeScript</p>
            </div>
          </div>
          <div className="hidden sm:flex items-center gap-1 text-xs text-slate-500 bg-white border border-slate-200 rounded-lg px-3 py-1.5">
            <FolderOpen size={13} /> {files.length} file{files.length !== 1 ? "s" : ""} &middot; {totalLines.toLocaleString()} lines
          </div>
        </div>

        {/* Nav */}
        <div className="flex flex-wrap gap-1.5 mb-6 bg-white border border-slate-200 rounded-xl p-1.5 w-fit">
          <NavItem id="upload" icon={Upload} label="Upload & analyze" />
          <NavItem id="dashboard" icon={Gauge} label="Dashboard" />
          <NavItem id="issues" icon={Bug} label={`Issues${analyzed ? ` (${issues.length})` : ""}`} />
          <NavItem id="review" icon={Sparkles} label="AI review" />
        </div>

        {/* UPLOAD TAB */}
        {tab === "upload" && (
          <div className="space-y-5">
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <h2 className="text-sm font-semibold mb-1">Project files</h2>
              <p className="text-xs text-slate-500 mb-4">Upload .py, .js, .jsx, .ts or .tsx files, or paste a snippet below. A sample two-file project is loaded so you can try it immediately.</p>

              <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg mb-4">
                {files.map((f) => (
                  <div key={f.name} className="flex items-center justify-between px-3.5 py-2.5">
                    <div className="flex items-center gap-2 text-sm">
                      <FileCode2 size={15} className="text-slate-400" />
                      <span className="font-medium">{f.name}</span>
                      <span className="text-xs text-slate-400">{f.content.split("\n").length} lines</span>
                    </div>
                    <button onClick={() => removeFile(f.name)} className="text-slate-400 hover:text-red-600 p-1">
                      <X size={14} />
                    </button>
                  </div>
                ))}
                {files.length === 0 && (
                  <div className="px-3.5 py-6 text-center text-sm text-slate-400">No files yet — upload or paste code below.</div>
                )}
              </div>

              <div className="flex flex-wrap gap-2 mb-5">
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-1.5 text-sm font-medium border border-slate-300 rounded-lg px-3.5 py-2 hover:bg-slate-50"
                >
                  <Upload size={14} /> Upload files
                </button>
                <input ref={fileInputRef} type="file" multiple accept=".py,.js,.jsx,.ts,.tsx" onChange={handleFileUpload} className="hidden" />
                <button
                  onClick={runAnalysis}
                  disabled={files.length === 0}
                  className="flex items-center gap-1.5 text-sm font-medium bg-slate-900 text-white rounded-lg px-3.5 py-2 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play size={14} /> Run analysis
                </button>
              </div>

              <div className="border-t border-slate-100 pt-4">
                <h3 className="text-xs font-semibold text-slate-600 mb-2">Paste a snippet</h3>
                <div className="flex gap-2 mb-2">
                  <input
                    value={pasteFilename}
                    onChange={(e) => setPasteFilename(e.target.value)}
                    className="text-xs border border-slate-300 rounded-md px-2 py-1.5 w-40"
                    placeholder="filename.py"
                  />
                </div>
                <textarea
                  value={pasteText}
                  onChange={(e) => setPasteText(e.target.value)}
                  placeholder="Paste Python, JavaScript, or TypeScript code here..."
                  className="w-full h-28 text-xs font-mono border border-slate-300 rounded-md p-2.5 mb-2"
                />
                <button
                  onClick={addPastedSnippet}
                  disabled={!pasteText.trim()}
                  className="text-xs font-medium border border-slate-300 rounded-lg px-3 py-1.5 hover:bg-slate-50 disabled:opacity-40"
                >
                  Add snippet to project
                </button>
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-start gap-3">
              <HelpCircle size={16} className="text-slate-400 mt-0.5 shrink-0" />
              <p className="text-xs text-slate-500 leading-relaxed">
                Analysis runs entirely against the code you provide, using real pattern-based static checks (credential exposure, injection-prone patterns, unsafe deserialization, weak hashing, long/complex functions, duplication, unused variables). Nothing is fabricated — every finding below links back to an exact file and line. "AI review" and "explain with AI" additionally call Claude for natural-language analysis grounded in your actual code.
              </p>
            </div>
          </div>
        )}

        {/* DASHBOARD TAB */}
        {tab === "dashboard" && (
          <div className="space-y-5">
            {!analyzed ? (
              <EmptyState onGo={() => setTab("upload")} label="Add files and run analysis to see your dashboard." />
            ) : (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <ScoreRing label="Code quality" value={scores.quality} icon={ClipboardList} />
                  <ScoreRing label="Security" value={scores.security} icon={ShieldAlert} />
                  <ScoreRing label="Maintainability" value={scores.maintainability} icon={Layers} />
                  <ScoreRing label="Complexity" value={scores.complexity} icon={Gauge} />
                </div>

                <div className="grid sm:grid-cols-3 gap-3">
                  <MetricCard label="Files analyzed" value={files.length} />
                  <MetricCard label="Lines of code" value={totalLines.toLocaleString()} />
                  <MetricCard label="Overall score" value={`${scores.overall}/100`} />
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-5">
                  <h2 className="text-sm font-semibold mb-3">Issues by severity</h2>
                  <div style={{ height: 220 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#eef2f6" vertical={false} />
                        <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} />
                        <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} />
                        <Tooltip cursor={{ fill: "#f8fafc" }} />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                          {chartData.map((entry) => (
                            <Cell key={entry.name} fill={
                              { CRITICAL: "#dc2626", HIGH: "#f97316", MEDIUM: "#d97706", LOW: "#3b82f6", INFO: "#94a3b8" }[entry.name]
                            } />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-1">
                    <h2 className="text-sm font-semibold">Scoring formula</h2>
                  </div>
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Each score starts at 100 and subtracts a weighted penalty per issue found in its category (Critical −25, High −15, Medium −8, Low −3, Info −0). Quality, maintainability, and complexity penalties are additionally scaled by 0.6&times;/0.5&times;/0.5&times; since they're less severe than direct security findings. Overall is the unweighted average of the four category scores, floored at 0. No score is set by hand.
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* ISSUES TAB */}
        {tab === "issues" && (
          <div className="space-y-4">
            {!analyzed ? (
              <EmptyState onGo={() => setTab("upload")} label="Add files and run analysis to see issues." />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative flex-1 min-w-[200px]">
                    <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder='Search findings — e.g. "authentication", "injection"'
                      className="w-full text-sm border border-slate-300 rounded-lg pl-8 pr-3 py-2"
                    />
                  </div>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="text-sm border border-slate-300 rounded-lg px-2.5 py-2"
                  >
                    <option value="ALL">All severities</option>
                    {SEVERITY.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <p className="text-[11px] text-slate-400 -mt-2">Keyword search over titles/explanations — a full deployment would back this with embeddings + pgvector for true semantic search.</p>

                <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100">
                  {filteredIssues.length === 0 && (
                    <div className="px-4 py-8 text-center text-sm text-slate-400">No findings match this filter.</div>
                  )}
                  {filteredIssues.map((issue) => (
                    <button
                      key={issue.id}
                      onClick={() => setSelectedIssue(issue)}
                      className="w-full flex items-center justify-between text-left px-4 py-3 hover:bg-slate-50"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <SeverityBadge severity={issue.severity} />
                          <CategoryTag category={issue.category} />
                        </div>
                        <p className="text-sm font-medium truncate">{issue.title}</p>
                        <p className="text-xs text-slate-400 font-mono">{issue.file}{issue.line ? `:${issue.line}` : ""}</p>
                      </div>
                      <ChevronRight size={16} className="text-slate-300 shrink-0" />
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {/* AI REVIEW TAB */}
        {tab === "review" && (
          <div className="space-y-4">
            {!analyzed ? (
              <EmptyState onGo={() => setTab("upload")} label="Add files and run analysis, then generate an AI review." />
            ) : (
              <div className="bg-white border border-slate-200 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h2 className="text-sm font-semibold flex items-center gap-1.5"><Sparkles size={15} className="text-amber-500" /> AI code review</h2>
                    <p className="text-xs text-slate-500">Claude reviews architecture, readability, maintainability, error handling, performance, and security across your uploaded files.</p>
                  </div>
                  <button
                    onClick={generateAiReview}
                    disabled={aiReview.loading}
                    className="flex items-center gap-1.5 text-sm font-medium bg-slate-900 text-white rounded-lg px-3.5 py-2 hover:bg-slate-800 disabled:opacity-50 shrink-0"
                  >
                    {aiReview.loading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                    {aiReview.loading ? "Reviewing..." : "Generate review"}
                  </button>
                </div>
                {aiReview.text ? (
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-slate-700 border-t border-slate-100 pt-4">{aiReview.text}</div>
                ) : (
                  !aiReview.loading && <p className="text-xs text-slate-400 border-t border-slate-100 pt-4">No review generated yet.</p>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ISSUE DETAIL PANEL */}
      {selectedIssue && (
        <div className="fixed inset-0 bg-slate-900/30 flex items-center justify-center z-50 p-4" onClick={() => setSelectedIssue(null)}>
          <div className="bg-white rounded-xl max-w-xl w-full max-h-[85vh] overflow-y-auto p-5" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={selectedIssue.severity} />
                <CategoryTag category={selectedIssue.category} />
              </div>
              <button onClick={() => setSelectedIssue(null)} className="text-slate-400 hover:text-slate-700"><X size={18} /></button>
            </div>
            <h2 className="text-base font-semibold mb-1">{selectedIssue.title}</h2>
            <p className="text-xs text-slate-400 font-mono mb-4">{selectedIssue.file}{selectedIssue.line ? `:${selectedIssue.line}` : ""}</p>

            {selectedIssue.snippet && (
              <pre className="text-xs font-mono bg-slate-900 text-slate-100 rounded-lg p-3 mb-4 overflow-x-auto">
                <span className="text-amber-400 select-none">{selectedIssue.line}| </span>{selectedIssue.snippet}
              </pre>
            )}

            <div className="mb-3">
              <h3 className="text-xs font-semibold text-slate-500 mb-1">Problem</h3>
              <p className="text-sm text-slate-700">{selectedIssue.explain}</p>
            </div>
            <div className="mb-4">
              <h3 className="text-xs font-semibold text-slate-500 mb-1">Suggested fix</h3>
              <p className="text-sm text-slate-700">{selectedIssue.fix}</p>
            </div>

            <div className="border-t border-slate-100 pt-4">
              {!aiExplain[selectedIssue.id]?.text && (
                <button
                  onClick={() => explainIssue(selectedIssue)}
                  disabled={aiExplain[selectedIssue.id]?.loading}
                  className="flex items-center gap-1.5 text-sm font-medium border border-slate-300 rounded-lg px-3 py-1.5 hover:bg-slate-50 disabled:opacity-50"
                >
                  {aiExplain[selectedIssue.id]?.loading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} className="text-amber-500" />}
                  {aiExplain[selectedIssue.id]?.loading ? "Asking Claude..." : "Explain with AI"}
                </button>
              )}
              {aiExplain[selectedIssue.id]?.text && (
                <div className="bg-amber-50 border border-amber-100 rounded-lg p-3">
                  <h3 className="text-xs font-semibold text-amber-800 mb-1 flex items-center gap-1"><Sparkles size={12} /> Claude's take</h3>
                  <p className="text-sm text-amber-900 whitespace-pre-wrap">{aiExplain[selectedIssue.id].text}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function MetricCard({ label, value }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className="text-xl font-semibold">{value}</p>
    </div>
  );
}

function EmptyState({ label, onGo }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-10 flex flex-col items-center text-center gap-3">
      <AlertCircle size={22} className="text-slate-300" />
      <p className="text-sm text-slate-500">{label}</p>
      <button onClick={onGo} className="text-sm font-medium bg-slate-900 text-white rounded-lg px-3.5 py-2">
        Go to upload
      </button>
    </div>
  );
}
