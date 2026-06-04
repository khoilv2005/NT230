const form = document.getElementById("analyzeForm");
const packageInput = document.getElementById("packageInput");
const versionInput = document.getElementById("versionInput");
const crewaiInput = document.getElementById("crewaiInput");
const explainInput = document.getElementById("explainInput");
const submitButton = document.getElementById("submitButton");

const healthDot = document.getElementById("healthDot");
const healthTitle = document.getElementById("healthTitle");
const healthText = document.getElementById("healthText");
const runState = document.getElementById("runState");
const runMeta = document.getElementById("runMeta");

const emptyState = document.getElementById("emptyState");
const loadingState = document.getElementById("loadingState");
const resultView = document.getElementById("resultView");
const errorView = document.getElementById("errorView");
const errorText = document.getElementById("errorText");

const verdictCard = document.getElementById("verdictCard");
const verdictLabel = document.getElementById("verdictLabel");
const verdictSummary = document.getElementById("verdictSummary");
const filesSeen = document.getElementById("filesSeen");
const flaggedFiles = document.getElementById("flaggedFiles");
const elapsedTime = document.getElementById("elapsedTime");
const traceCount = document.getElementById("traceCount");
const traceList = document.getElementById("traceList");
const rationaleText = document.getElementById("rationaleText");
const fileCount = document.getElementById("fileCount");
const fileTable = document.getElementById("fileTable");

function setView(view) {
  emptyState.classList.toggle("hidden", view !== "empty");
  loadingState.classList.toggle("hidden", view !== "loading");
  resultView.classList.toggle("hidden", view !== "result");
  errorView.classList.toggle("hidden", view !== "error");
}

function setRunState(label, mode) {
  runState.textContent = label;
  runState.className = `run-state ${mode}`;
}

function escapeText(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatScore(value) {
  const num = Number(value || 0);
  return Number.isFinite(num) ? num.toFixed(3) : "0.000";
}

function renderTrace(steps) {
  traceCount.textContent = `${steps.length} steps`;
  traceList.innerHTML = steps
    .map((step, index) => {
      const output = step.output || {};
      const detail =
        output.archive_path ||
        `${output.n_files ?? output.n_malicious ?? ""} files` ||
        output.label ||
        "";
      return `
        <article class="trace-step">
          <strong>${index + 1}. ${escapeText(step.agent)}</strong>
          <code>${escapeText(step.action)}${detail ? ` · ${escapeText(detail)}` : ""}</code>
        </article>
      `;
    })
    .join("");
}

function renderFiles(files) {
  fileCount.textContent = `${files.length} files`;
  if (!files.length) {
    fileTable.innerHTML = `<tr><td colspan="3">No Python files selected.</td></tr>`;
    return;
  }
  fileTable.innerHTML = files
    .map((file) => {
      const label = String(file.label || "").toLowerCase();
      const pillClass = label === "malicious" ? "malicious" : "benign";
      return `
        <tr>
          <td class="path-cell">${escapeText(file.path)}</td>
          <td><span class="pill ${pillClass}">${escapeText(label || "-")}</span></td>
          <td>${formatScore(file.score)}</td>
        </tr>
      `;
    })
    .join("");
}

function renderResult(data) {
  const verdict = data.verdict || {};
  const label = String(verdict.label || "unknown").toLowerCase();
  const isMalicious = label === "malicious";
  const maliciousCount = (verdict.malicious_files || []).length;
  const totalFiles = Number(verdict.n_files || data.files?.length || 0);

  verdictCard.classList.toggle("malicious", isMalicious);
  verdictLabel.className = isMalicious ? "malicious" : "benign";
  verdictLabel.textContent = label.toUpperCase();
  verdictSummary.textContent = isMalicious
    ? "At least one file was classified as malicious."
    : "No selected file was classified as malicious.";

  filesSeen.textContent = totalFiles.toLocaleString();
  flaggedFiles.textContent = maliciousCount.toLocaleString();
  elapsedTime.textContent = `${data.elapsed_sec || 0}s`;
  rationaleText.textContent = verdict.rationale || "No rationale returned.";

  const version = data.fetch?.version ? `==${data.fetch.version}` : "";
  runMeta.textContent = `${data.package}${version}`;
  renderTrace(data.crew_execution || []);
  renderFiles(data.files || []);
  setRunState(isMalicious ? "Malicious" : "Benign", "done");
  setView("result");
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    healthDot.classList.toggle("ok", Boolean(data.checkpoint_exists));
    healthTitle.textContent = data.checkpoint_exists ? "Runtime ready" : "Model missing";
    healthText.textContent = data.checkpoint_exists
      ? `Ollama key ${data.ollama_key}.`
      : `Missing checkpoint: ${data.default_checkpoint}`;
  } catch (error) {
    healthDot.classList.remove("ok");
    healthTitle.textContent = "Backend unavailable";
    healthText.textContent = error.message;
  }
}

async function analyze(event) {
  event.preventDefault();
  const packageName = packageInput.value.trim();
  if (!packageName) {
    packageInput.focus();
    return;
  }

  submitButton.disabled = true;
  setRunState("Running", "running");
  runMeta.textContent = `${packageName}${versionInput.value.trim() ? `==${versionInput.value.trim()}` : ""}`;
  setView("loading");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: packageName,
        version: versionInput.value.trim() || null,
        use_crewai: crewaiInput.checked,
        explain: explainInput.checked,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Analysis failed.");
    }
    renderResult(data);
  } catch (error) {
    setRunState("Error", "error");
    errorText.textContent = error.message;
    setView("error");
  } finally {
    submitButton.disabled = false;
  }
}

document.querySelectorAll(".sample-button").forEach((button) => {
  button.addEventListener("click", () => {
    packageInput.value = button.dataset.package || "";
    versionInput.value = button.dataset.version || "";
    packageInput.focus();
  });
});

form.addEventListener("submit", analyze);
checkHealth();
