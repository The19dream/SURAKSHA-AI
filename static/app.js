// Suraksha AI — Front-End Application Logic

document.addEventListener("DOMContentLoaded", () => {
  // Common Init
  updateNavbarActiveLink();
  
  // Route-Specific Init
  const path = window.location.pathname;
  if (path === "/" || path.endsWith("index.html") || path === "") {
    initDashboard();
  } else if (path.endsWith("scam.html")) {
    initScamChecker();
  } else if (path.endsWith("note.html")) {
    initNoteChecker();
  } else if (path.endsWith("map.html")) {
    initHotspotMap();
  } else if (path.endsWith("audit.html")) {
    initAuditLog();
  }

  // Trigger Lucide icons creation if available
  if (typeof lucide !== "undefined") {
    lucide.createIcons();
  }
});

// Helper to set active nav link based on current path
function updateNavbarActiveLink() {
  const path = window.location.pathname;
  const navLinks = document.querySelectorAll("nav a");
  navLinks.forEach(link => {
    const href = link.getAttribute("href");
    if (href && path.endsWith(href)) {
      link.classList.remove("text-slate-300", "hover:text-white");
      link.classList.add("text-blue-400", "border-b-2", "border-blue-500", "font-medium");
    }
  });
}

// --------------------------------------------------------
// DASHBOARD (index.html)
// --------------------------------------------------------
async function initDashboard() {
  const totalScansEl = document.getElementById("stat-total-scans");
  const highRiskEl = document.getElementById("stat-high-risk");
  const notesCheckedEl = document.getElementById("stat-notes-checked");
  const lowRiskEl = document.getElementById("stat-low-risk");

  try {
    const res = await fetch("/api/stats");
    if (!res.ok) throw new Error("Failed to fetch dashboard stats");
    const stats = await res.json();
    
    // Update stats with counts, fallback to zero
    if (totalScansEl) totalScansEl.textContent = stats.total_scans || 0;
    if (highRiskEl) highRiskEl.textContent = stats.high_risk_count || 0;
    if (notesCheckedEl) notesCheckedEl.textContent = stats.notes_checked || 0;
    if (lowRiskEl) lowRiskEl.textContent = stats.low_risk_count || 0;
  } catch (error) {
    console.error("Dashboard init error:", error);
  }
}

// --------------------------------------------------------
// SCAM MESSAGE CHECKER (scam.html)
// --------------------------------------------------------
async function initScamChecker() {
  const textarea = document.getElementById("scam-text-input");
  const analyzeBtn = document.getElementById("analyze-scam-btn");
  const btnText = document.getElementById("btn-text");
  const spinner = document.getElementById("btn-spinner");
  
  const resultsContainer = document.getElementById("scam-results");
  const sampleDropdown = document.getElementById("sample-dropdown");
  
  // Pipeline steps
  const stepDetect = document.getElementById("step-detect");
  const stepVerify = document.getElementById("step-verify");
  const stepReport = document.getElementById("step-report");

  // Load sample messages into dropdown
  try {
    const response = await fetch("/api/sample-messages");
    if (response.ok) {
      const samples = await response.json();
      samples.forEach(sample => {
        const option = document.createElement("option");
        option.value = sample.id;
        option.textContent = `${sample.type === "scam" ? "⚠️" : "✅"} ${sample.label}`;
        sampleDropdown.appendChild(option);
      });
      
      sampleDropdown.addEventListener("change", (e) => {
        const selectedId = parseInt(e.target.value);
        const match = samples.find(s => s.id === selectedId);
        if (match) {
          textarea.value = match.text;
        } else {
          textarea.value = "";
        }
      });
    }
  } catch (err) {
    console.error("Failed to load sample messages:", err);
  }

  // Trigger analysis
  analyzeBtn.addEventListener("click", async () => {
    const text = textarea.value.trim();
    if (!text) {
      alert("Please enter some text or load a sample first!");
      return;
    }

    // Set Loading state
    analyzeBtn.disabled = true;
    btnText.textContent = "Processing Pipeline...";
    spinner.classList.remove("hidden");
    resultsContainer.classList.add("hidden");
    
    // Reset Pipeline visuals
    resetPipelineSteps();

    try {
      // Step 1: Trigger Detection Visual
      await sleep(600);
      activatePipelineStep(stepDetect, "active");
      
      // Send actual request
      const startTime = Date.now();
      const res = await fetch("/api/scam/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });
      
      if (!res.ok) throw new Error("Failed to scan message");
      const data = await res.json();
      
      // Pipeline animation sequence
      await sleep(800);
      activatePipelineStep(stepDetect, "success");
      activatePipelineStep(stepVerify, "active");
      
      await sleep(1000);
      activatePipelineStep(stepVerify, "success");
      
      if (data.pipeline_steps.reporting_complete) {
        activatePipelineStep(stepReport, "active");
        await sleep(700);
        activatePipelineStep(stepReport, "success");
      } else {
        activatePipelineStep(stepReport, "muted");
      }

      // Display results
      renderScamResults(data);
      
    } catch (error) {
      console.error(error);
      alert("Error executing safety pipeline: " + error.message);
    } finally {
      // Revert button
      analyzeBtn.disabled = false;
      btnText.textContent = "Scan Message";
      spinner.classList.add("hidden");
    }
  });

  function resetPipelineSteps() {
    [stepDetect, stepVerify, stepReport].forEach(step => {
      if (step) {
        step.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/50 text-slate-500 pipeline-step";
        const icon = step.querySelector(".step-icon");
        if (icon) icon.innerHTML = "●";
      }
    });
  }

  function activatePipelineStep(element, state) {
    if (!element) return;
    const icon = element.querySelector(".step-icon");
    if (state === "active") {
      element.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-blue-500 bg-blue-950/20 text-blue-400 font-medium pipeline-step pulse-blue";
      if (icon) icon.innerHTML = "⚡";
    } else if (state === "success") {
      element.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-emerald-500 bg-emerald-950/20 text-emerald-400 font-medium pipeline-step";
      if (icon) icon.innerHTML = "✓";
    } else if (state === "muted") {
      element.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/20 text-slate-600 line-through pipeline-step";
      if (icon) icon.innerHTML = "○";
    }
  }

  function renderScamResults(data) {
    resultsContainer.classList.remove("hidden");
    
    // Risk Level details
    const riskBadge = document.getElementById("scam-risk-badge");
    const riskBg = document.getElementById("scam-risk-bg");
    const riskTitle = document.getElementById("scam-risk-title");
    const confidenceEl = document.getElementById("scam-confidence");
    const verdictEl = document.getElementById("scam-verdict-summary");
    
    const risk = data.risk_level;
    
    // Set colors according to risk
    riskBadge.className = "px-3 py-1 rounded text-xs font-bold uppercase tracking-wider";
    riskBg.className = "p-6 rounded-t-xl border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4";
    
    if (risk === "HIGH") {
      riskBadge.classList.add("bg-red-950", "text-red-400", "border", "border-red-500");
      riskBg.classList.add("bg-red-950/10");
      riskTitle.className = "text-xl font-bold text-red-500";
    } else if (risk === "MEDIUM") {
      riskBadge.classList.add("bg-amber-950", "text-amber-400", "border", "border-amber-500");
      riskBg.classList.add("bg-amber-950/10");
      riskTitle.className = "text-xl font-bold text-amber-500";
    } else if (risk === "NEEDS_REVIEW") {
      riskBadge.classList.add("bg-slate-800", "text-slate-300", "border", "border-slate-500");
      riskBg.classList.add("bg-slate-800/15");
      riskTitle.className = "text-xl font-bold text-slate-300";
    } else {
      riskBadge.classList.add("bg-emerald-950", "text-emerald-400", "border", "border-emerald-500");
      riskBg.classList.add("bg-emerald-950/10");
      riskTitle.className = "text-xl font-bold text-emerald-500";
    }

    riskTitle.textContent = `${risk} RISK LEVEL`;
    confidenceEl.textContent = ` Confidence: ${(data.confidence * 100).toFixed(0)}%`;
    verdictEl.textContent = data.verdict;
    
    // Reasons list
    const reasonsList = document.getElementById("scam-reasons");
    reasonsList.innerHTML = "";
    const reasonsSource = data.reasons || [];
    reasonsSource.forEach(reason => {
      const li = document.createElement("li");
      li.className = "text-slate-300 flex items-start space-x-2";
      li.innerHTML = `<span class="text-blue-500 mt-1">▪</span> <span>${reason}</span>`;
      reasonsList.appendChild(li);
    });

    // Evidence Details
    const evidencePre = document.getElementById("scam-evidence-data");
    evidencePre.textContent = JSON.stringify(data.evidence || {}, null, 2);

    const reportingDiv = document.getElementById("scam-reporting-guidance");
    if (reportingDiv) {
      reportingDiv.classList.add("hidden");
    }
  }
}

// --------------------------------------------------------
// COUNTERFEIT NOTE CHECKER (note.html)
// --------------------------------------------------------
function initNoteChecker() {
  const fileInput = document.getElementById("note-file-input");
  const uploadArea = document.getElementById("upload-area");
  const imgPreviewContainer = document.getElementById("image-preview-container");
  const imgPreview = document.getElementById("image-preview");
  const analyzeBtn = document.getElementById("analyze-note-btn");
  const btnText = document.getElementById("note-btn-text");
  const spinner = document.getElementById("note-btn-spinner");
  
  const resultsContainer = document.getElementById("note-results");
  // Open file picker when upload area is clicked
uploadArea.addEventListener("click", () => {
    fileInput.click();
});
  
  
  // Drag & drop handlers
  ["dragenter", "dragover"].forEach(eventName => {
    uploadArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      uploadArea.classList.add("border-blue-500", "bg-blue-950/10");
    }, false);
  });

  ["dragleave", "drop"].forEach(eventName => {
    uploadArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      uploadArea.classList.remove("border-blue-500", "bg-blue-950/10");
    }, false);
  });

  uploadArea.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length) {
      fileInput.files = files;
      handleFileSelected(files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onloadend = () => {
      imgPreview.src = reader.result;
      imgPreviewContainer.classList.remove("hidden");
      analyzeBtn.disabled = false;
      resultsContainer.classList.add("hidden");
    };
  }

  // Preset quick upload helper buttons for demo!
  const presetGood = document.getElementById("demo-real-note");
  const presetBad = document.getElementById("demo-fake-note");

  if (presetGood) {
    presetGood.addEventListener("click", () => {
      imgPreview.src = "https://images.unsplash.com/photo-1627012422668-3f398e256b8a?auto=format&fit=crop&w=500&q=80"; // standard note-like graphic
      imgPreviewContainer.classList.remove("hidden");
      analyzeBtn.disabled = false;
      resultsContainer.classList.add("hidden");
      
      // Inject pseudo file with matching name to trigger mock router!
      createAndSetPseudoFile("genuine_note_500.jpg");
    });
  }

  if (presetBad) {
    presetBad.addEventListener("click", () => {
      imgPreview.src = "https://images.unsplash.com/photo-1590283603385-17ffb3a7f29f?auto=format&fit=crop&w=500&q=80"; // warning-like graphic
      imgPreviewContainer.classList.remove("hidden");
      analyzeBtn.disabled = false;
      resultsContainer.classList.add("hidden");
      
      createAndSetPseudoFile("counterfeit_fake_500.jpg");
    });
  }

  function createAndSetPseudoFile(filename) {
    // We create a tiny blank blob with a specific name so standard multipart upload picks up the filename rule
    const blob = new Blob([""], { type: "image/jpeg" });
    const file = new File([blob], filename, { type: "image/jpeg" });
    
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;
  }

  // Trigger analysis
  analyzeBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];
    // Allow proceeding even with preloaded external Unsplash image (we fallback to mock filename if file is empty)
    
    analyzeBtn.disabled = true;
    btnText.textContent = "Analyzing Note Canvas...";
    spinner.classList.remove("hidden");
    resultsContainer.classList.add("hidden");

    // Pipeline visuals
    const stepScan = document.getElementById("step-note-scan");
    const stepTactile = document.getElementById("step-note-tactile");
    resetNoteSteps();

    try {
      await sleep(800);
      activateNoteStep(stepScan, "active");
      
      // Build form data
      const formData = new FormData();
      if (file) {
        formData.append("file", file);
      } else {
        // Create fallback file based on current preview source name to allow presets to work flawlessly
        const isFake = imgPreview.src.includes("1590283603385") || fileInput.files[0]?.name?.includes("fake");
        const fallbackName = isFake ? "counterfeit_fake_500.jpg" : "genuine_note_500.jpg";
        const blob = new Blob([""], { type: "image/jpeg" });
        formData.append("file", new File([blob], fallbackName, { type: "image/jpeg" }));
      }

      const res = await fetch("/api/note/check", {
        method: "POST",
        body: formData
      });

      if (!res.ok) throw new Error("Verification failed");
      const data = await res.json();

      await sleep(1000);
      activateNoteStep(stepScan, "success");
      activateNoteStep(stepTactile, "active");
      
      await sleep(800);
      activateNoteStep(stepTactile, "success");

      renderNoteResults(data);

    } catch (error) {
      console.error(error);
      alert("Error scanning banknote: " + error.message);
    } finally {
      analyzeBtn.disabled = false;
      btnText.textContent = "Verify Banknote";
      spinner.classList.add("hidden");
    }
  });

  function resetNoteSteps() {
    ["step-note-scan", "step-note-tactile"].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/50 text-slate-500 pipeline-step";
        const icon = el.querySelector(".step-icon");
        if (icon) icon.innerHTML = "●";
      }
    });
  }

  function activateNoteStep(element, state) {
    if (!element) return;
    const icon = element.querySelector(".step-icon");
    if (state === "active") {
      element.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-blue-500 bg-blue-950/20 text-blue-400 font-medium pipeline-step pulse-blue";
      if (icon) icon.innerHTML = "⚡";
    } else if (state === "success") {
      element.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-emerald-500 bg-emerald-950/20 text-emerald-400 font-medium pipeline-step";
      if (icon) icon.innerHTML = "✓";
    }
  }

  function renderNoteResults(data) {
    resultsContainer.classList.remove("hidden");
    const evidence = data.evidence || {};
    
    const riskBadge = document.getElementById("note-risk-badge");
    const riskBg = document.getElementById("note-risk-bg");
    const riskTitle = document.getElementById("note-risk-title");
    const verdictEl = document.getElementById("note-verdict-summary");
    const serialEl = document.getElementById("note-serial");
    
    const risk = data.risk_level;
    
    riskBadge.className = "px-3 py-1 rounded text-xs font-bold uppercase tracking-wider";
    riskBg.className = "p-6 rounded-t-xl border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4";
    
    if (risk === "HIGH") {
      riskBadge.classList.add("bg-red-950", "text-red-400", "border", "border-red-500");
      riskBg.classList.add("bg-red-950/10");
      riskTitle.className = "text-xl font-bold text-red-500";
    } else if (risk === "NEEDS_REVIEW") {
      riskBadge.classList.add("bg-slate-800", "text-slate-300", "border", "border-slate-500");
      riskBg.classList.add("bg-slate-800/15");
      riskTitle.className = "text-xl font-bold text-slate-300";
    } else {
      riskBadge.classList.add("bg-emerald-950", "text-emerald-400", "border", "border-emerald-500");
      riskBg.classList.add("bg-emerald-950/10");
      riskTitle.className = "text-xl font-bold text-emerald-500";
    }

    riskTitle.textContent = `${risk} RISK VERDICT`;
    verdictEl.textContent = data.verdict;
    serialEl.textContent =
   `Banknote Serial: ${evidence.serial_number || "NOT DETECTED"}`;

    // Reasons
    const reasonsList = document.getElementById("note-reasons");
    reasonsList.innerHTML = "";
    (evidence.reasons || []).forEach(reason => {
      const li = document.createElement("li");
      li.className = "text-slate-300 flex items-start space-x-2 text-sm";
      li.innerHTML = `<span class="text-blue-500 mt-1">▪</span> <span>${reason}</span>`;
      reasonsList.appendChild(li);
    });

    // Checklist table
    const checklistBody = document.getElementById("note-checklist-body");
    checklistBody.innerHTML = "";
    const checks = evidence.checks || {};
    
    Object.entries(checks).forEach(([key, val]) => {
      const tr = document.createElement("tr");
      tr.className = "border-b border-slate-900 bg-slate-950/20";
      
      const isPassed = val.toLowerCase().includes("pass") || val.toLowerCase().includes("visible");
      const isFailed = val.toLowerCase().includes("fail");
      
      let statusBadge = `<span class="text-slate-400 text-xs">${val}</span>`;
      if (isPassed) {
        statusBadge = `<span class="px-2 py-0.5 rounded-full text-2xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-500/30">✓ PASS</span>`;
      } else if (isFailed) {
        statusBadge = `<span class="px-2 py-0.5 rounded-full text-2xs font-semibold bg-red-950 text-red-400 border border-red-500/30">⚠️ FAIL</span>`;
      }

      // Format check title (snake_case to human)
      const label = key.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");

      tr.innerHTML = `
        <td class="px-4 py-3 text-sm font-medium text-slate-300 font-display">${label}</td>
        <td class="px-4 py-3 text-right">${statusBadge}</td>
      `;
      checklistBody.appendChild(tr);
    });

    // Next steps
    const stepsList = document.getElementById("note-next-steps");
    stepsList.innerHTML = "";
    (evidence.next_steps || []).forEach(step => {
      const li = document.createElement("li");
      li.className = "text-sm text-slate-300 leading-relaxed";
      li.textContent = step;
      stepsList.appendChild(li);
    });
  }
}

// --------------------------------------------------------
// CYBERCRIME HOTSPOT MAP (map.html)
// --------------------------------------------------------
async function initHotspotMap() {
  const mapContainer = document.getElementById("map-canvas");
  if (!mapContainer) return;

  // Initialize Leaflet Map centered on central India
  const map = L.map("map-canvas").setView([21.7679, 78.8718], 5);

  // Add highly professional custom dark matter layer (CartoDB Dark Matter)
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains: "abcd",
    maxZoom: 20
  }).addTo(map);

  try {
    const res = await fetch("/api/hotspots");
    if (!res.ok) throw new Error("Could not load hotspots database");
    const hotspots = await res.json();

    hotspots.forEach(record => {
      // Color-coding based on crime type
      let markerColor = "#3b82f6"; // Blue default
      if (record.type === "Digital Arrest") {
        markerColor = "#ef4444"; // Red for high danger coercion
      } else if (record.type.toLowerCase().includes("counterfeit")) {
        markerColor = "#f59e0b"; // Amber
      } else if (record.type.toLowerCase().includes("upi") || record.type.toLowerCase().includes("fraud")) {
        markerColor = "#10b981"; // Emerald
      } else if (record.type.toLowerCase().includes("sextortion")) {
        markerColor = "#ec4899"; // Pink
      }

      // Circle marker
      const circle = L.circleMarker([record.lat, record.lng], {
        color: markerColor,
        fillColor: markerColor,
        fillOpacity: 0.45,
        radius: 8,
        weight: 1.5
      }).addTo(map);

      // Popup content
      const popupHtml = `
        <div class="p-1 leading-relaxed max-w-xs">
          <div class="flex items-center justify-between gap-3 mb-1.5 border-b border-slate-700 pb-1">
            <span class="text-xs font-bold font-mono tracking-wide px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 uppercase">${record.type}</span>
            <span class="text-3xs text-slate-400 font-mono">${record.date}</span>
          </div>
          <h4 class="font-bold text-sm text-white mb-0.5 font-display">${record.city}</h4>
          <p class="text-xs text-slate-300">${record.description}</p>
        </div>
      `;

      circle.on("click", async () => {

    try {

        const response = await fetch("/api/hotspot/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(record)
        });

        const ai = await response.json();

        const popupHtml = `
            <div class="p-2 max-w-sm">
                <h3><b>${record.city}</b></h3>

                <p><b>Crime:</b> ${record.type}</p>
                <p>${record.description}</p>

                <hr>

                <p><b>AI Verdict:</b> ${ai.verdict}</p>

                <p><b>Risk:</b> ${ai.risk_level}</p>

                <p><b>Confidence:</b>
                ${(ai.confidence * 100).toFixed(0)}%</p>

                <b>Reasons</b>

                <ul>
                    ${ai.reasons.map(r => `<li>${r}</li>`).join("")}
                </ul>

                <b>Safety Tips</b>

                <ul>
                    ${ai.next_steps.map(s => `<li>${s}</li>`).join("")}
                </ul>
            </div>
        `;

        circle.bindPopup(popupHtml).openPopup();

    }

    catch (err) {

        console.error(err);

        circle.bindPopup(`
            <b>${record.city}</b><br>
            AI analysis unavailable.
        `).openPopup();

    }

});
    });

  } catch (error) {
    console.error("Hotspot mapping failed:", error);
  }
}

// --------------------------------------------------------
// AUDIT LOG (audit.html)
// --------------------------------------------------------
async function initAuditLog() {
  const tableBody = document.getElementById("audit-table-body");
  if (!tableBody) return;

  try {
    const res = await fetch("/api/audit-log");
    if (!res.ok) throw new Error("Failed to load audit trail");
    const logs = await res.json();

    tableBody.innerHTML = "";
    if (logs.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="5" class="px-6 py-12 text-center text-sm text-slate-500 font-mono">
            No pipeline runs logged in the audit trail yet. Try running a scam scan or banknote check!
          </td>
        </tr>
      `;
      return;
    }

    logs.forEach(log => {
      const tr = document.createElement("tr");
      tr.className = "border-b border-slate-900 hover:bg-slate-900/30 transition-colors";

      // Time formatting
      const date = new Date(log.timestamp);
      const timeStr = new Date(log.timestamp).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: false });

      // Risk level color badge
      const risk = log.risk_level;
      let badgeClass = "bg-slate-800 text-slate-300 border-slate-600";
      if (risk === "HIGH") badgeClass = "bg-red-950/40 text-red-400 border-red-500/30";
      else if (risk === "MEDIUM") badgeClass = "bg-amber-950/40 text-amber-400 border-amber-500/30";
      else if (risk === "LOW") badgeClass = "bg-emerald-950/40 text-emerald-400 border-emerald-500/30";

      const riskBadge = `<span class="px-2 py-0.5 rounded border text-3xs font-semibold uppercase tracking-wider ${badgeClass}">${risk}</span>`;

      // Input snippet safe styling
      const safeSnippet = log.input_text || "N/A";

      tr.innerHTML = `
        <td class="px-6 py-4 whitespace-nowrap text-xs text-slate-400 font-mono">${timeStr} IST</td>
        <td class="px-6 py-4 whitespace-nowrap text-xs font-mono font-medium text-blue-400 select-all">${log.input_hash}</td>
        <td class="px-6 py-4 text-xs font-medium text-slate-200 font-display">${log.verdict}</td>
        <td class="px-6 py-4 whitespace-nowrap">${riskBadge}</td>
        <td class="px-6 py-4 whitespace-nowrap text-xs text-slate-300 font-mono">${((log.confidence || 0) * 100).toFixed(0)}%</td>
      `;
      tableBody.appendChild(tr);
    });

  } catch (error) {
    console.error("Audit load error:", error);
    tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="px-6 py-8 text-center text-sm text-red-400 font-mono">
          Failed to retrieve audit trail logs: ${error.message}
        </td>
      </tr>
    `;
  }
}
  


// Utility: sleep delay
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
