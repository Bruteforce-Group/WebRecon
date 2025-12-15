async function jsonFetch(url, opts = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const msg = (data && data.detail) ? data.detail : (typeof data === "string" ? data : "Request failed");
    throw new Error(msg);
  }
  return data;
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.appendChild(c);
  return node;
}

function link(label, href) {
  return el("a", { href, target: "_blank", rel: "noreferrer", class: "link", text: label });
}

function button(label, onClick, kind = "secondary") {
  const btn = el("button", { type: "button", class: `btn btn-${kind}`, text: label });
  btn.addEventListener("click", onClick);
  return btn;
}

async function loadFileText(scanId, path) {
  // Use plain fetch here because some responses are non-JSON (HTML/MD).
  const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/file?path=${encodeURIComponent(path)}`);
  if (!res.ok) throw new Error(`Failed to load file (${res.status})`);
  return await res.text();
}

async function loadReportJson(scanId, path) {
  const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/file?path=${encodeURIComponent(path)}`);
  if (!res.ok) throw new Error(`Failed to load report (${res.status})`);
  const text = await res.text();
  try {
    return { kind: "json", value: JSON.parse(text) };
  } catch {
    return { kind: "text", value: text };
  }
}

function renderResults(container, resp) {
  container.innerHTML = "";

  container.appendChild(el("div", { class: "subtle", text: `Scan ID: ${resp.scan_id}` }));

  const previewWrap = el("div", { class: "preview-wrap" });
  const previewHeader = el("div", { class: "preview-header" }, [
    el("div", { class: "subtle", text: "Preview" }),
  ]);
  const preview = el("pre", { class: "preview", text: "Select a report to preview it here." });
  previewWrap.appendChild(previewHeader);
  previewWrap.appendChild(preview);

  if (resp.ai_analysis_html) {
    container.appendChild(el("div", { class: "row" }, [
      el("span", { class: "badge", text: "AI" }),
      link("Open AI analysis (HTML)", `/api/scans/${resp.scan_id}/file?path=${encodeURIComponent(resp.ai_analysis_html)}`),
      link("Download AI analysis (MD)", `/api/scans/${resp.scan_id}/file?path=${encodeURIComponent(resp.ai_analysis_md)}`),
      button("Preview (MD)", async () => {
        const status = document.getElementById("status");
        try {
          status.textContent = "Loading AI analysis…";
          preview.textContent = await loadFileText(resp.scan_id, resp.ai_analysis_md);
          status.textContent = "Done.";
        } catch (err) {
          status.textContent = `Error: ${err.message || err}`;
        }
      }),
    ]));
  } else {
    container.appendChild(el("div", { class: "subtle", text: "AI analysis not generated (or failed)."}));
  }

  const list = el("div", { class: "list" });
  for (const a of resp.artifacts) {
    const reportUrl = `/api/scans/${resp.scan_id}/file?path=${encodeURIComponent(a.report_path)}`;
    const row = el("div", { class: "row" }, [
      el("span", { class: "badge", text: a.scheme.toUpperCase() }),
      el("span", { text: a.domain }),
      button("Preview", async () => {
        const status = document.getElementById("status");
        try {
          status.textContent = `Loading ${a.domain} (${a.scheme})…`;
          const loaded = await loadReportJson(resp.scan_id, a.report_path);
          preview.textContent =
            loaded.kind === "json" ? JSON.stringify(loaded.value, null, 2) : String(loaded.value);
          status.textContent = "Done.";
        } catch (err) {
          status.textContent = `Error: ${err.message || err}`;
        }
      }),
      link("Open JSON", reportUrl),
    ]);
    list.appendChild(row);
  }
  container.appendChild(list);
  container.appendChild(previewWrap);
}

document.getElementById("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("status");
  const results = document.getElementById("results");
  const runBtn = document.getElementById("runBtn");

  try {
    status.textContent = "";
    runBtn.disabled = true;
    runBtn.textContent = "Running…";

    const domains = document.getElementById("domains").value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    const payload = {
      domains,
      schemes: document.getElementById("schemes").value,
      max_pages: Number(document.getElementById("maxPages").value || 5),
      max_depth: Number(document.getElementById("maxDepth").value || 1),
      ignore_robots: document.getElementById("ignoreRobots").checked,
      generate_ai_analysis: document.getElementById("aiAnalysis").checked,
      acknowledge_authorization: document.getElementById("authz").checked,
    };

    status.textContent = "Submitting scan…";
    const resp = await jsonFetch("/api/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    status.textContent = "Done.";
    renderResults(results, resp);
  } catch (err) {
    status.textContent = `Error: ${err.message || err}`;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run scan";
  }
});


