const API_BASE = "http://127.0.0.1:5000";

const checkBtn  = document.getElementById("checkBtn");
const resultBox = document.getElementById("result");

function showResult(message, cssClass = "") {
  resultBox.innerText = message;

  resultBox.classList.remove("safe", "suspicious", "malicious", "error");
  if (cssClass) {
    resultBox.classList.add(cssClass);
  }
}

function statusToClass(status) {
  switch ((status || "").toLowerCase()) {
    case "safe": return "safe";
    case "suspicious": return "suspicious";
    case "malicious": return "malicious";
    default: return "";
  }
}

async function handleCheckClick() {

  console.log("Button clicked");

  checkBtn.disabled = true;
  showResult("🔍 Scanning…");

  try {
    const [activeTab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!activeTab || !activeTab.url) {
      showResult("⚠️ Could not retrieve URL", "error");
      return;
    }

    const url = activeTab.url;

    if (
      url.startsWith("chrome://") ||
      url.startsWith("chrome-extension://")
    ) {
      showResult("⚠️ Internal Chrome page", "error");
      return;
    }

    const response = await fetch(`${API_BASE}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      showResult(`❌ Server error (HTTP ${response.status})`, "error");
      return;
    }

    const data = await response.json();

    const status  = data.status || "Unknown";
    const details = data.details || "";

    const emoji =
      { safe: "✅", suspicious: "⚠️", malicious: "🚨" }[
        status.toLowerCase()
      ] || "ℹ️";

    // 🔥 FIXED CLEAN OUTPUT (THIS IS THE ONLY CHANGE)
    const finalOutput =
      `${emoji} ${status}\n\n${details}\n\n🌐 URL: ${url}`;

    showResult(finalOutput, statusToClass(status));

  } catch (error) {
    showResult(
      "🔌 Backend not reachable. Make sure Flask is running.",
      "error"
    );

    console.error("Popup error:", error);

  } finally {
    checkBtn.disabled = false;
  }
}

checkBtn.addEventListener("click", handleCheckClick);