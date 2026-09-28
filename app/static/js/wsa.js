/* WSA shared frontend runtime: live updates, notifications, helpers. */
(function () {
  "use strict";

  const WSA = {
    pollTimer: null,
    refreshers: [],   // fns registered by pages to reload their data
    usingSocket: false,
    notifs: [],
  };

  // ---------- helpers ----------
  WSA.fmt = function fmt(n) { return (n ?? 0).toLocaleString(); };

  WSA.ago = function ago(iso) {
    if (!iso) return "-";
    const s = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  };

  WSA.sevBadge = function sevBadge(sev) {
    return `<span class="wsa-sev ${sev}">${sev}</span>`;
  };

  WSA.statusBadge = function statusBadge(st) {
    const icon = st === "running" ? '<i class="bi bi-arrow-repeat wsa-spin"></i> ' : "";
    return `<span class="wsa-status ${st}">${icon}${st}</span>`;
  };

  WSA.toast = function toast(msg, type = "", ms = 4200) {
    // Confirmations and status updates no longer pop up: a single scan used to
    // stack "queued / started / completed" boxes on screen. Everything is still
    // recorded in the notification bell. Warnings and errors do pop up, so a
    // rejected action (e.g. missing authorisation) still gives visible feedback.
    if (type !== "error" && type !== "warn") return;
    const box = document.getElementById("wsaToasts");
    if (!box) return;
    const el = document.createElement("div");
    el.className = "wsa-toast " + type;
    const icon = type === "success" ? "check-circle" : type === "error" ? "exclamation-octagon" :
                 type === "warn" ? "exclamation-triangle" : "info-circle";
    el.innerHTML = `<i class="bi bi-${icon}"></i><span></span>`;
    el.querySelector("span").textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), ms);
  };

  WSA.truncate = function (s, n = 48) {
    s = s || "";
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  };

  WSA.refreshNow = function refreshNow() {
    WSA.refreshers.forEach((fn) => { try { fn(); } catch (e) { console.error(e); } });
    WSA.stampUpdated();
  };

  WSA.stampUpdated = function stampUpdated() {
    const el = document.getElementById("lastUpdated");
    if (el) el.innerHTML = '<i class="bi bi-clock-history"></i> Updated ' + new Date().toLocaleTimeString();
  };

  WSA.notify = function notify(title, body) {
    WSA.notifs.unshift({ title, body, at: new Date() });
    WSA.notifs = WSA.notifs.slice(0, 30);
    renderNotifs();
    const bell = document.getElementById("notifBell");
    if (bell) bell.classList.add("text-primary");
  };

  function renderNotifs() {
    const list = document.getElementById("notifList");
    const count = document.getElementById("notifCount");
    if (!list) return;
    if (WSA.notifs.length === 0) {
      list.innerHTML = '<div class="wsa-notif-empty">No notifications yet.</div>';
    } else {
      list.innerHTML = WSA.notifs.map((n) =>
        `<div class="wsa-notif-item"><b>${n.title}</b><br>${n.body}
         <div class="wsa-cell-muted">${n.at.toLocaleTimeString()}</div></div>`).join("");
    }
    if (count) {
      count.hidden = WSA.notifs.length === 0;
      count.textContent = WSA.notifs.length;
    }
  }

  // ---------- api ----------
  WSA.api = async function api(url, opts = {}) {
    const resp = await fetch(url, {
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    let data = {};
    try { data = await resp.json(); } catch (_) { /* non-JSON */ }
    if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);
    return data;
  };

  // ---------- live updates: Socket.IO with polling fallback ----------
  function startPolling(reason) {
    if (WSA.pollTimer) return;
    console.warn("[WSA] Using polling fallback (" + reason + ")");
    WSA.usingSocket = false;
    setConn(false, "Live · polling");
    const secs = (window.WSA_POLL_SECONDS || 4) * 1000;
    WSA.pollTimer = setInterval(() => WSA.refreshNow(), secs);
  }

  function setConn(ok, label) {
    const badge = document.getElementById("wsaConnBadge");
    if (!badge) return;
    badge.innerHTML = `<span class="wsa-dot ${ok ? "" : "off"}"></span> ${label}`;
  }

  function connectSocket() {
    if (typeof io === "undefined") { startPolling("socket.io client unavailable"); return; }
    try {
      const sock = io({ transports: ["websocket", "polling"], timeout: 6000 });
      sock.on("connect", () => {
        WSA.usingSocket = true;
        setConn(true, "Live · realtime");
        if (WSA.pollTimer) { clearInterval(WSA.pollTimer); WSA.pollTimer = null; }
      });
      sock.on("disconnect", () => { setConn(false, "Reconnecting…"); });
      sock.on("scan_started", (d) => {
        WSA.notify("Scan Started", `#${d.scan_id} → ${WSA.truncate(d.target_url, 40)}`);
        WSA.toast(`Scan #${d.scan_id} started on ${WSA.truncate(d.target_url, 36)}`);
        WSA.refreshNow();
      });
      sock.on("scan_progress", (d) => {
        WSA.refreshers.forEach((fn) => { try { fn(d); } catch (e) {} });
      });
      sock.on("new_finding", (d) => {
        const sev = (d.severity || "informational").toUpperCase();
        // Findings surface in the Findings list (and the bell); they are not
        // pushed as popups -- a scan produces too many to stack on screen.
        WSA.notify("New Finding Discovered", `[${sev}] ${d.name}`);
        WSA.refreshNow();
      });
      sock.on("scan_completed", (d) => {
        const msg = d.status === "completed"
          ? `Scan #${d.scan_id} completed - ${d.findings_count ?? 0} finding(s)`
          : d.status === "failed" ? `Scan #${d.scan_id} failed: ${d.error || "unknown error"}`
          : `Scan #${d.scan_id} ${d.status}`;
        WSA.notify("Scan Completed", msg);
        WSA.toast(msg, d.status === "completed" ? "success" : d.status === "failed" ? "error" : "warn");
        WSA.refreshNow();
      });
      sock.on("connect_error", () => { if (!WSA.usingSocket) startPolling("connect error"); });
      setTimeout(() => { if (!sock.connected) startPolling("connection timeout"); }, 7000);
    } catch (e) {
      startPolling("socket init failed");
    }
  }

  // ---------- user dropdown / sign out ----------
  function initUserMenu() {
    const menu = document.getElementById("wsaUserMenu");
    const drop = document.getElementById("wsaUserDropdown");
    const signOut = document.getElementById("wsaSignOut");
    menu?.addEventListener("click", (e) => {
      e.stopPropagation();
      drop.hidden = !drop.hidden;
    });
    document.addEventListener("click", (e) => {
      if (drop && !drop.hidden && !drop.contains(e.target)) drop.hidden = true;
    });
    signOut?.addEventListener("click", async () => {
      try { await WSA.api("/api/auth/logout", { method: "POST" }); } catch (_) {}
      location.href = "/login";
    });
  }

  // ---------- collapsible sidebar ----------
  function initSidebar() {
    const sidebar = document.getElementById("wsaSidebar");
    const collapseBtn = document.getElementById("wsaCollapseBtn");
    if (!sidebar || !collapseBtn) return;

    // restore previous state (desktop only)
    if (localStorage.getItem("wsa-sidebar-collapsed") === "1") {
      sidebar.classList.add("collapsed");
      collapseBtn.setAttribute("aria-expanded", "false");
    }
    collapseBtn.addEventListener("click", () => {
      const collapsed = sidebar.classList.toggle("collapsed");
      collapseBtn.setAttribute("aria-expanded", String(!collapsed));
      collapseBtn.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
      localStorage.setItem("wsa-sidebar-collapsed", collapsed ? "1" : "0");
      setTimeout(() => window.dispatchEvent(new Event("resize")), 300);
    });
  }

  // ---------- global UI ----------
  function initChrome() {
    const burger = document.getElementById("wsaBurger");
    const sidebar = document.getElementById("wsaSidebar");
    const backdrop = document.getElementById("wsaBackdrop");
    burger?.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      backdrop.classList.toggle("show", sidebar.classList.contains("open"));
    });
    backdrop?.addEventListener("click", () => {
      sidebar.classList.remove("open");
      backdrop.classList.remove("show");
    });

    const bell = document.getElementById("notifBell");
    const panel = document.getElementById("notifPanel");
    bell?.addEventListener("click", (e) => { e.stopPropagation(); panel.hidden = !panel.hidden; });
    document.addEventListener("click", (e) => {
      if (panel && !panel.hidden && !panel.contains(e.target) && e.target !== bell) panel.hidden = true;
    });

    const search = document.getElementById("globalSearch");
    search?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const q = encodeURIComponent(search.value.trim());
        location.href = "/vulnerabilities" + (q ? `?search=${q}` : "");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initChrome();
    initUserMenu();
    initSidebar();
    connectSocket();
    WSA.refreshNow();

    // The socket only fires while a web scan is running (IP-scan events are not
    // relayed to these refreshers), so an idle page would keep showing whatever
    // it had on screen when it loaded. Refresh on a slow timer, and immediately
    // when the tab comes back into view, so the numbers always match the DB.
    setInterval(() => WSA.refreshNow(), 30000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) WSA.refreshNow();
    });
  });

  window.WSA = WSA;
})();
