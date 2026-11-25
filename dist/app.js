const NEW_USER_FORM_URL = "https://connect.streamlinedconsulting.online/q/new-account";
const $ = (s) => document.querySelector(s),
  esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
const icons = {
  logo: "M4 7h13l-4 4H4M20 17H7l4-4h9",
  grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  folder: "M3 6h6l2 2h10v12H3z",
  upload: "M12 16V3m-5 5 5-5 5 5M4 15v6h16v-6",
  download: "M12 3v13m-5-5 5 5 5-5M4 16v5h16v-5",
  activity: "M3 12h4l3-7 4 14 3-7h4",
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6zM8 12l3 3 5-6",
  clock: "M12 8v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0",
  gear: "M9 3h6l1 4 4 1v7l-4 1-1 5H9l-1-5-4-1V8l4-1zM15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0",
  users:
    "M15 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0M4 21v-3a6 6 0 0 1 12 0v3M18 5a3 3 0 0 1 0 6m1 3a5 5 0 0 1 3 4v3",
  bolt: "m13 2-8 12h6l-1 8 9-13h-7z",
  file: "M5 3h9l5 5v13H5zM14 3v6h5M8 14h8M8 17h6",
  image: "M3 3h18v18H3zM3 17l6-6 5 5 3-3 4 4M17 7h.01",
  check: "m5 12 4 4L19 6",
  arrow: "M4 12h16m-6-6 6 6-6 6",
  plus: "M12 4v16M4 12h16",
  search: "M16 16l5 5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  trash: "M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7",
  edit: "m4 16 12-12 4 4L8 20H4zM13 7l4 4",
  key: "M14 10a5 5 0 1 1-5-5 5 5 0 0 1 5 5m-3 4 10 7m-4-3 3-3M9 8h.01",
  logout: "M9 3H3v18h6M10 12h11m-4-4 4 4-4 4",
  help: "M9 8a3 3 0 1 1 5 2c-2 1-2 2-2 3M12 17h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0",
  bell: "M5 17h14l-2-4V9a5 5 0 0 0-10 0v4zM10 21h4",
  restore: "M3 10a9 9 0 1 1 1 9M3 3v7h7",
  close: "m5 5 14 14M5 19 19 5",
  pause: "M8 4v16M16 4v16",
  play: "m7 3 14 9-14 9z",
  building: "M4 21V3h12v18M16 9h5v12M8 7h4M8 11h4M8 15h4M2 21h21",
};
const icon = (n) =>
    `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${icons[n] || icons.file}"/></svg>`,
  brand = () =>
    `<div class="brand"><span class="brandmark">${icon("logo")}</span><div><strong>streamlined</strong><small>VAULT</small></div></div>`;
const bytes = (n) => {
    if (n >= 1e12) return (n / 1e12).toFixed(n % 1e12 ? 2 : 0) + " TB";
    if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
    return n + " B";
  },
  date = (v) =>
    v === "Never"
      ? "Never"
      : new Date(v).toLocaleString(undefined, {
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit",
        });
let clerkUI,
  authError = "",
  overviewScope = "all",
  inventoryBusy = false;
let config,
  preview = false,
  demoAPI,
  user,
  tenant,
  page = "Overview",
  data = {
    files: [],
    audit: [],
    devices: [],
    members: [],
    tokens: [],
    notices: [],
  },
  query = "",
  folder = "All folders",
  trash = false,
  transfers = [],
  toastTimer,
  renderCounter = 0;
const base = () => `/api/tenants/${encodeURIComponent(tenant)}`;
async function api(path, method = "GET", b, raw = false) {
  if (preview) return demoAPI.request(path, method, b);
  const jwt = clerkUI ? await clerkUI.token() : null;
  const r = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      ...(jwt ? { Authorization: "Bearer " + jwt } : {}),
      ...(raw
        ? {
            "Content-Type": "application/octet-stream",
            "X-Content-SHA256": await digest(b),
          }
        : b
          ? { "Content-Type": "application/json" }
          : {}),
      ...(method !== "GET" ? { "X-CSRF-Token": user?.csrf || "" } : {}),
    },
    ...(b !== undefined ? { body: raw ? b : JSON.stringify(b) } : {}),
  });
  const v = await r.json();
  if (!r.ok) {
    if (r.status === 401 && path !== "/api/me") {
      user = null;
      authError = v.error || "Please sign in";
      loginScreen();
    }
    const failure = Error(v.error || "Request failed");
    failure.code = v.code;
    throw failure;
  }
  return v;
}
async function digest(b) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", await b.arrayBuffer()),
    ),
  ]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}
function toast(t) {
  $("#toast").textContent = t;
  $("#toast").classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("#toast").classList.add("hidden"), 4500);
}
function modal(title, content, action, label = "Save") {
  const m = $("#modal");
  m.innerHTML = `<h2>${esc(title)}</h2>${content}<div class="formerror" role="alert"></div><div class="actions"><button id="cancel">Cancel</button>${action ? `<button id="confirm" class="primary">${esc(label)}</button>` : ""}</div>`;
  $("#cancel").onclick = () => m.close();
  if (action)
    $("#confirm").onclick = async () => {
      const button = $("#confirm");
      button.disabled = true;
      try {
        await action();
      } catch (e) {
        m.querySelector(".formerror").textContent = e.message;
      } finally {
        button.disabled = false;
      }
    };
  m.showModal();
}
const field = (label, id, value = "", type = "text") =>
  `<label class="field">${label}<input id="${id}" type="${type}" value="${esc(value)}" ${type === "text" ? 'maxlength="200"' : ""}></label>`;
async function refresh() {
  user = await api("/api/me");
  if (!tenant || !user.tenants.some((t) => t.id === tenant))
    tenant = user.tenants[0]?.id;
}
function loginScreen() {
  const isDemo = config?.demo || preview;
  $("#root").innerHTML =
    `<div class="login"><div class="loginart">${brand()}<div><span class="eyebrow">HIPAA-COMPLIANT CLOUD STORAGE</span><h1>Your practice data.<br>One controlled<br>workspace.</h1><p>Private practice storage with encrypted transfers, MFA-protected access, and scheduled file uploads.</p></div><p style="font-size:10px">STREAMLINED VAULT　 /　 CLIENT ACCESS</p><div class="rings"></div></div><div class="loginform"><div class="logininner"><div class="eyebrow">WELCOME TO STREAMLINED VAULT</div><h2>Storage built for your practice.</h2><p>Access your workspace or request a new account.</p><section class="access-menu" aria-label="Client access"><button id="access-open" class="access-open" aria-expanded="false" aria-controls="access-options">Client access ${icon("arrow")}</button><div id="access-options" class="access-options hidden"><button id="returning-user">${icon("key")}<span><strong>Returning user</strong><small>Sign in to your workspace</small></span>${icon("arrow")}</button>${NEW_USER_FORM_URL ? `<a href="${esc(NEW_USER_FORM_URL)}">${icon("plus")}<span><strong>New user</strong><small>Request an account</small></span>${icon("arrow")}</a>` : `<button disabled><span><strong>New user</strong><small>Account request form coming soon</small></span></button>`}</div></section><section id="returning-panel" class="hidden" aria-label="Returning user sign-in"><button id="access-back" class="quiet">${icon("arrow")}Back to access options</button>${isDemo ? `<div class="notice" style="margin-top:23px">${icon("shield")}Interactive preview · synthetic data only</div><p>Choose a view to explore. No password is needed for this preview.</p><div class="demochoices"><button data-login="client"><div><h3>Practice portal</h3><p>Upload, organize, and download files</p></div>${icon("arrow")}</button><button data-login="msp"><div><h3>MSP management</h3><p>Manage practices, access, and uploaders</p></div>${icon("arrow")}</button></div><small>${preview ? "Files selected in this preview stay in browser memory and disappear on refresh." : "Local test files stay on this development computer."} Do not use patient data or real credentials.</small>` : `<div id="clerk-sign-in" style="margin-top:24px"></div><p id="clerk-auth-error" role="alert" style="color:#a45f4f;margin-top:16px"></p><button id="clerk-sign-out" class="primary hidden">Sign out and verify again</button><button id="clerk-security" class="hidden" style="margin-top:12px">Account security</button><small>Use your verified practice account and authenticator-app MFA. Authenticator codes come from your authenticator app, not email. Need access? Contact your practice administrator.</small>`}</section></div></div></div>`;
  document.querySelectorAll("[data-login]").forEach(
    (b) =>
      (b.onclick = async () => {
        b.disabled = true;
        try {
          user = await api("/auth/demo", "POST", { role: b.dataset.login });
          await refresh();
          await navigate("Overview");
        } catch (e) {
          toast(e.message);
          b.disabled = false;
        }
      }),
  );
  const revealAccess = () => {
    $("#access-open").disabled = true;
    $("#access-open").setAttribute("aria-expanded", "true");
    $("#access-options").classList.remove("hidden");
  };
  $("#access-open").onclick = () => {
    revealAccess();
    $("#returning-user").focus();
  };
  let mounted = false;
  const showReturning = () => {
    $(".access-menu").classList.add("hidden");
    $("#returning-panel").classList.remove("hidden");
    if (!isDemo && clerkUI && !clerkUI.signedIn() && !mounted) {
      clerkUI.mountSignIn($("#clerk-sign-in"), {signUpUrl:NEW_USER_FORM_URL});
      mounted = true;
    }
    $("#access-back").focus();
  };
  $("#returning-user").onclick = showReturning;
  $("#access-back").onclick = () => {
    $("#returning-panel").classList.add("hidden");
    $(".access-menu").classList.remove("hidden");
    revealAccess();
    $("#returning-user").focus();
  };
  if (!isDemo && clerkUI?.signedIn()) {
    showReturning();
    $("#clerk-auth-error").textContent = authError || "Complete your MFA sign-in to continue.";
    $("#clerk-sign-out").classList.remove("hidden");
    $("#clerk-sign-out").onclick = () => clerkUI.signOut();
    $("#clerk-security").classList.remove("hidden");
    $("#clerk-security").onclick = () => clerkUI.openSecurity();
  }

}
const tabs = [
  ["Overview", "grid"],
  ["Files", "folder"],
  ["Transfers", "upload"],
  ["Uploaders", "upload"],
  ["Activity", "activity"],
  ["Team & access", "users"],
  ["Settings", "gear"],
  ["Plan & usage", "shield"],
];
function activationBanner() {
  if (config.demo)
    return `<div class="notice">${icon("shield")}Preview workspace. All examples are synthetic. Cloud storage and identity are not connected.</div>`;
  // Detailed activation and onboarding states live in their own settings views.
  // The persistent header status remains visible without a page-wide warning.
  return "";
}
function shell() {
  const t = user.tenants.find((t) => t.id === tenant),
    used = t?.used || 0;
  const nav = tabs.filter(
    ([p]) =>
      (!["Team & access", "Uploaders"].includes(p) ||
        t?.role === "admin" ||
        user.msp) &&
      !(t?.kind === "internal" && p === "Team & access"),
  );
  const label = (p) => ({"Team & access":"Users & access", "Settings":"Workspace settings", "Client workspaces":"Practices", "MSP settings":"My MSP settings"}[p] || p);
  const navButton = ([p, i]) => `<button title="${label(p)}" data-page="${p}" ${page === p ? 'aria-current="page"' : ''} class="${page === p ? "active" : ""}">${icon(i)}<span class="navtext">${label(p)}</span></button>`;
  const navigation = `${user.msp ? `<section class="navgroup"><div class="navlabel">MSP ADMINISTRATION</div>${[["Client workspaces","building"],["Security & logs","shield"],["MSP settings","gear"]].map(navButton).join("")}</section>` : ""}<section class="navgroup"><div class="navlabel">${esc(t?.name || "SELECTED WORKSPACE")}</div>${nav.map(navButton).join("")}</section>`;
  $("#root").innerHTML =
    `<aside class="sidebar">${brand()}<div class="workspace"><label>${user.msp ? "SELECTED WORKSPACE" : "YOUR PRACTICE"}</label><select id="workspace" aria-label="Select practice">${user.tenants.map((t) => `<option value="${t.id}" ${tenant === t.id ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select></div><nav aria-label="Main navigation">${navigation}</nav><div class="sidebarbottom"><h3 style="font-size:11px">Selected workspace storage</h3><div class="storagebar"><i style="width:${Math.min(100, (used / 4e12) * 100)}%"></i></div><div class="storagetext"><span>${bytes(used)} used</span><span>4 TB plan</span></div><div class="support">${icon("help")}<button class="quiet" data-action="help" style="font-size:11px">Need a hand?</button></div></div></aside><div class="main"><header><div class="breadcrumb">${["Client workspaces", "MSP settings", "Security & logs"].includes(page) || (page === "Overview" && user.msp && overviewScope === "all") ? "MSP console" : "Workspace"}　/　<b>${esc(label(page))}</b></div><div class="headeractions"><span class="badge ${config.demo ? "amber" : ""}">${config.demo ? "PREVIEW · NO PHI" : icon("shield") + (config.ready ? "PRIVATE WORKSPACE" : "ACTIVATION REVIEW")}</span><button class="quiet" title="Notifications" data-action="notices">${icon("bell")}</button><span class="avatar">${user.msp ? "MS" : "PA"}</span><button class="quiet" title="Sign out" data-action="logout">${icon("logout")}</button></div></header><div class="content"><div class="titlebar"><div><span class="eyebrow">${user.msp ? "MANAGED WITH CARE" : "YOUR FILES, BEAUTIFULLY ORGANIZED"}</span><h1 id="heading"></h1><p id="subtitle"></p></div><div class="actions" id="pageactions"></div></div>${activationBanner()}<div id="pagebody"><div class="empty">Opening workspace…</div></div><footer class="footer"><span>Streamlined Vault　·　${esc(["Client workspaces", "MSP settings", "Security & logs"].includes(page) || (page === "Overview" && user.msp && overviewScope === "all") ? "MSP console" : t?.name || "MSP console")}</span><span>${preview ? "Browser preview · resets on refresh" : config.demo ? "Local test environment" : "Managed client storage"}</span></footer></div></div>`;
  $("#workspace").onchange = async (e) => {
    tenant = e.target.value;
    overviewScope = "workspace";
    query = "";
    folder = "All folders";
    await navigate(page);
  };
  document
    .querySelectorAll("[data-page]")
    .forEach((b) => (b.onclick = () => navigate(b.dataset.page)));
}
async function navigate(p) {
  page = p;
  const count = ++renderCounter;
  shell();
  let t = user.tenants.find((t) => t.id === tenant);
  const titles = {
    Overview: [
      "Workspace overview.",
      "Your practice’s files, transfers, and storage in one clear view.",
    ],
    Files: [
      trash ? "Recently deleted" : "All your files. One place.",
      "Organize, upload, and retrieve your practice’s files.",
    ],
    Transfers: [
      "Every transfer, accounted for.",
      "Follow upload progress and retry interrupted transfers.",
    ],
    Uploaders: [
      "Your uploads. On your schedule.",
      "Connect practice computers and automatically upload new and changed files.",
    ],
    Activity: [
      "A clear record of what happened.",
      "Review file access, administrative changes, and automated tasks.",
    ],
    "Team & access": [
      "The right access. For the right people.",
      "Manage who can view, upload, and administer this practice.",
    ],
    Settings: [
      "Your workspace, your way.",
      "Review storage, access, and service configuration.",
    ],
    "Security & logs": [
      "Security, with evidence.",
      "Protected logs, maintenance health, alerts and live verification.",
    ],
    "MSP settings": [
      "Your MSP. Your workspace.",
      "Account settings, private storage and the default client plan.",
    ],
    "Plan & usage": [
      "Your plan, clearly explained.",
      "Storage, transfers, file limits and additional services.",
    ],
    "Client workspaces": [
      "Every practice. One clear view.",
      "Provision and manage client workspaces with a 4 TB allowance.",
    ],
  };
  $("#heading").textContent = titles[p][0];
  $("#subtitle").textContent = titles[p][1];
  const action = $("#pageactions");
  if (["Overview", "Files"].includes(p))
    action.innerHTML = `<button data-action="newfolder">${icon("folder")}New folder</button><button class="primary" data-action="upload">${icon("plus")}Upload files</button>`;
  if (p === "Uploaders")
    action.innerHTML = `<button class="primary" data-action="newdevice">${icon("plus")}Add uploader</button>`;
  if (p === "Activity")
    action.innerHTML = `<button data-action="export">${icon("download")}Export activity</button>`;
  if (p === "Team & access")
    action.innerHTML = `<button class="primary" data-action="invite">${icon("plus")}Add user</button>`;
  if (p === "Client workspaces")
    action.innerHTML = `<button class="primary" data-action="newclient">${icon("plus")}Add practice</button>`;
  if (p === "Overview" && user.msp) {
    if (overviewScope === "all") action.innerHTML = "";
    action.insertAdjacentHTML(
      "afterbegin",
      `<div class="overview-switch" role="group" aria-label="Overview scope"><button data-overviewscope="all" aria-pressed="${overviewScope === "all"}">All clients</button><button data-overviewscope="workspace" aria-pressed="${overviewScope === "workspace"}">Selected workspace</button></div>`,
    );
  }
  try {
    if (p === "Security & logs") {
      data.security = await api("/api/msp/security");
      if (count === renderCounter) renderSecurity();
      return;
    }
    if (p === "MSP settings") {
      data.mspSettings = await api("/api/msp/settings");
      if (count === renderCounter) renderMspSettings();
      return;
    }
    if (p === "Overview" && user.msp && overviewScope === "all") {
      $("#heading").textContent = "Your MSP at a glance.";
      $("#subtitle").textContent =
        "All client workspaces, portal traffic and provider inventory.";
      data.msp = await api("/api/msp/overview");
      if (count === renderCounter) renderMspOverview();
      return;
    }
    if (p === "Plan & usage" && tenant) {
      data.plan = await api(base() + "/plan");
      if (count === renderCounter) renderPlan();
      return;
    }
    if (p === "Transfers") {
      renderTransfers();
      return;
    }
    if (p === "Client workspaces") {
      await refresh();
      if (count === renderCounter) renderClients();
      return;
    }
    if (!tenant) {
      $("#pagebody").innerHTML = empty(
        "No practices yet",
        "Add a client workspace to get started.",
      );
      return;
    }
    const filesPromise =
      t?.role === "uploader"
        ? Promise.resolve({ files: [], used: t.used })
        : api(
            base() + "/files" + (trash && p === "Files" ? "?trash=true" : ""),
          );
    if (["Overview", "Files", "Settings"].includes(p)) {
      const f = await filesPromise;
      if (count !== renderCounter) return;
      data.files = f.files;
      t.used = f.used;
    }
    if (["Overview", "Activity"].includes(p))
      data.audit = t?.role === "uploader" ? [] : await api(base() + "/audit");
    if (["Overview", "Uploaders"].includes(p))
      data.devices =
        user.msp || t?.role === "admin" ? await api(base() + "/devices") : [];
    if (p === "Team & access") data.members = await api(base() + "/members");
    if (count !== renderCounter) return;
    ({
      Overview: renderOverview,
      Files: renderFiles,
      Uploaders: renderUploaders,
      Activity: renderAudit,
      "Team & access": renderTeam,
      Settings: renderSettings,
    })[p]();
    wireDrop();
  } catch (e) {
    if (count === renderCounter && $("#pagebody"))
      $("#pagebody").innerHTML =
        `<div class="errorpanel">${esc(e.message)} <button data-action="refresh">Try again</button></div>`;
  }
}
function empty(title, sub) {
  return `<div class="empty">${icon("folder")}<h3>${esc(title)}</h3><p>${esc(sub)}</p></div>`;
}
function filetable(files) {
  return files.length
    ? `<div class="tablewrap"><table><thead><tr><th>File name</th><th>Size</th><th>Added</th><th>Status</th><th><span class="hidden">Actions</span></th></tr></thead><tbody>${files.map((f) => `<tr><td><div class="filecell"><span class="fileicon ${/\.(dcm|jpg|png|tif)$/i.test(f.name) ? "image" : ""}">${icon(/\.(dcm|jpg|png|tif)$/i.test(f.name) ? "image" : "file")}</span><span>${esc(f.name)}<small>${esc(f.folder || "General")}</small></span></div></td><td>${bytes(f.size)}</td><td style="white-space:nowrap;color:#8797a3">${date(f.created)}</td><td><span class="tag">${f.status === "trash" ? "Recoverable" : config.demo ? "Sample" : "Stored"}</span></td><td><div class="rowactions">${f.status === "trash" ? `<button title="Restore file" data-restore="${f.id}">${icon("restore")}</button>` : `<button title="Download file" data-download="${f.id}">${icon("download")}</button><button title="Rename file" data-rename="${f.id}">${icon("edit")}</button><button title="Move to trash" data-trash="${f.id}">${icon("trash")}</button>`}</div></td></tr>`).join("")}</tbody></table></div>`
    : empty(
        trash ? "Trash is empty" : "Make room for what matters",
        "Upload your first file to get started.",
      );
}
function drop() {
  return `<div class="dropzone" id="dropzone" role="button" tabindex="0" aria-label="Upload files"><span class="dropicon">${icon("upload")}</span><div><h3>Drop files here. We’ll take it from here.</h3><p>Choose files within your plan’s current upload limit.</p></div><button data-action="upload">Browse files ${icon("arrow")}</button></div>`;
}
function renderOverview() {
  const t = user.tenants.find((t) => t.id === tenant),
    used = t.used || 0,
    autos = data.devices.filter((a) => !a.revoked && a.last_seen).length;
  $("#pagebody").innerHTML =
    `<div class="banner">${icon("shield")}<div><h3>${config.demo ? "A workspace built around your practice" : "Welcome to your practice workspace"}</h3><p>${config.demo ? "Explore your files and workflows with safe, synthetic examples." : "Private file access with role-based permissions and an activity trail."}</p></div><span class="badge">${icon("check")}4 TB storage plan</span></div><div class="stats">${[
      [`Storage used`, "folder", bytes(used), `of your 4 TB allowance`],
      [
        `Files stored`,
        "file",
        data.files.length.toLocaleString(),
        `Across your workspace`,
      ],
      [
        `Available space`,
        "shield",
        bytes(Math.max(0, 4e12 - used)),
        `${(100 - (used / 4e12) * 100).toFixed(1)}% of your plan available`,
      ],
      [
        `Enrolled uploaders`,
        "bolt",
        String(autos),
        `Practice computers connected`,
      ],
    ]
      .map(
        ([l, i, v, h]) =>
          `<div class="card stat"><label>${l}${icon(i)}</label><strong>${v}</strong><span class="hint ${i === "shield" ? "green" : ""}">${h}</span></div>`,
      )
      .join(
        "",
      )}</div><div class="grid"><div>${drop()}<div class="card"><div class="cardhead"><h2>Recent files</h2><button class="quiet" data-nav="Files" style="font-size:11px;color:var(--accent)">View all files ${icon("arrow")}</button></div>${filetable(data.files.slice(0, 5))}</div><div class="card section quickcard"><div class="legend"><i></i>YOUR PLAN AT A GLANCE<b>${bytes(used)} / 4 TB</b></div><div class="storagebar" style="height:8px"><i style="width:${(used / 4e12) * 100}%"></i></div><p>Storage includes files in trash and reserved space for unfinished uploads.</p></div></div><div class="rightcol"><div class="card"><div class="cardhead"><h2>Recent activity</h2><span style="color:#9da9b0;font-size:10px">WORKSPACE</span></div><div class="recent">${
      data.audit
        .slice(0, 4)
        .map(
          (e) =>
            `<div class="event"><span class="eventicon">${icon("check")}</span><div><h3>${esc(e.action)}</h3><p>${esc(e.actor === "demo" ? "Practice workspace" : e.actor)}</p><time>${date(e.created)}</time></div></div>`,
        )
        .join("") || "<p>No activity yet.</p>"
    }</div><div style="padding:0 20px 20px"><button data-nav="Activity" style="width:100%;font-size:11px">Open activity log ${icon("arrow")}</button></div></div><div class="card section quickcard"><div class="automationicon" style="margin-bottom:17px">${icon("bolt")}</div><h2>One less thing to remember.</h2><p style="margin-top:10px">Schedule new and changed files to upload from your practice computers.</p><button data-nav="Uploaders">Manage uploaders ${icon("arrow")}</button></div></div></div>`;
}
const fileLimit = (n) =>
  n >= 1024 ** 3
    ? (n / 1024 ** 3).toFixed(0) + " GiB"
    : (n / 1024 ** 2).toFixed(0) + " MiB";
const dollars = (cents) =>
  cents === null || cents === undefined
    ? "Not set"
    : new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
      }).format(cents / 100);
function metric(label, value, note) {
  return `<div class="card stat"><label>${esc(label)}</label><strong>${esc(value)}</strong><span class="hint">${esc(note)}</span></div>`;
}
function renderMspOverview() {
  const m = data.msp,
    p = m.provider,
    snapshot = p.snapshot;
  $("#pagebody").innerHTML =
    `<div class="stats">${metric("Client storage", bytes(m.totals.used), "Portal quota usage; includes trash and unfinished uploads")}${metric("Client workspaces", String(m.totals.clients), "Your private MSP workspace is listed separately")}${metric("Downloads this month", bytes(m.totals.downloadedBytes), m.period + " UTC · authorized download bytes")}${metric("Provider inventory", snapshot ? bytes(snapshot.bytes) : "Not scanned", snapshot ? "Completed object versions as of " + date(snapshot.capturedAt) : "Refresh to measure account-wide retained storage")}</div><div class="card"><div class="cardhead"><h2>Client workspace usage</h2><button data-action="newclient">Add practice</button></div><div class="tablewrap"><table><thead><tr><th>Practice</th><th>Storage / allowance</th><th>Uploaded this month</th><th>Downloaded this month</th><th>Storage status</th><th></th></tr></thead><tbody>${m.clients.map((t) => `<tr><td><strong>${esc(t.name)}</strong><small>${esc(t.status)}</small></td><td>${bytes(t.used)} / ${bytes(t.quota)}<div class="storagebar"><i style="width:${Math.min(100, (100 * t.used) / t.quota)}%"></i></div></td><td>${bytes(t.meter.uploadedBytes)}</td><td>${bytes(t.meter.downloadedBytes)}</td><td>${esc(t.storage.status)}</td><td><button data-client="${t.id}">Open workspace</button></td></tr>`).join("") || '<tr><td colspan="6">No client workspaces yet.</td></tr>'}</tbody></table></div></div><div class="detailgrid section"><div class="card section-panel"><div class="cardhead"><h2>Provider storage inventory</h2><button data-action="providerinventory" ${inventoryBusy ? "disabled" : ""}>${inventoryBusy ? "Scanning…" : p.status === "scanning" ? "Continue scan" : "Refresh inventory"}</button></div><div class="panel-content"><p>${snapshot ? `<strong>${bytes(snapshot.bytes)}</strong> across ${snapshot.buckets.length} buckets and ${snapshot.versions.toLocaleString()} completed object versions.` : "No completed inventory scan yet."}</p><p>This scan includes all buckets visible to the account credential, including stored versions outside the portal. Unfinished multipart parts are excluded. Scans are point-in-time estimates and do not represent monthly average storage or your invoice.</p>${p.status === "scanning" ? '<div class="notice">Scan in progress. The last completed snapshot remains displayed; continue the scan if you leave this page.</div>' : ""}${p.status === "error" ? '<div class="notice">The last scan needs attention. Its previous completed snapshot remains available.</div>' : ""}${snapshot?.buckets.length ? `<details><summary>Bucket breakdown</summary>${snapshot.buckets.map((b) => `<div class="row"><span>${esc(b.name)}</span><strong>${bytes(b.bytes)}</strong></div>`).join("")}</details>` : ""}</div></div><div class="card section-panel"><div class="cardhead"><h2>Your private MSP workspace</h2><button data-nav="MSP settings">MSP settings</button></div><div class="panel-content">${m.internal.length ? m.internal.map((t) => `<h3>${esc(t.name)}</h3><p>${bytes(t.used)} used · ${esc(t.storage.status)}</p><button data-internal="${t.id}">Open my workspace</button>`).join("") : "<p>Create your own private workspace and dedicated bucket from MSP settings. It is kept separate from client workspaces.</p>"}<p>Portal transfer tracking started ${date(m.trackingSince)}. Retries and range downloads count as traffic. Direct provider traffic, API fees and hosting charges require separate billing reconciliation.</p></div></div></div>`;
}
function planFields(p = {}) {
  return `<div class="plan-form"><label class="field">Included downloads per month (TB, decimal)<input id="plan-download" type="number" min="0" step="0.1" value="${p.downloadLimitBytes === null || p.downloadLimitBytes === undefined ? "" : p.downloadLimitBytes / 1e12}" placeholder="Not set"></label><label class="field">When the download allowance is reached<select id="plan-mode"><option value="notice" ${p.downloadMode !== "block" ? "selected" : ""}>Show allowance and overage information</option><option value="block" ${p.downloadMode === "block" ? "selected" : ""}>Block further downloads until reviewed</option></select></label><label class="field">Download overage price (USD per GB)<input id="plan-download-rate" type="number" min="0" step="0.01" value="${p.downloadOverageCentsPerGB === null || p.downloadOverageCentsPerGB === undefined ? "" : p.downloadOverageCentsPerGB / 100}" placeholder="Not set"></label><label class="field">Additional storage price (USD per TB/month, by agreement)<input id="plan-storage-rate" type="number" min="0" step="0.01" value="${p.storageUpgradeCentsPerTB === null || p.storageUpgradeCentsPerTB === undefined ? "" : p.storageUpgradeCentsPerTB / 100}" placeholder="Not set"></label><label class="field">Additional services and terms<textarea id="plan-services" rows="4" maxlength="2000">${esc(p.additionalServices || "")}</textarea></label><label class="publish-plan"><input id="plan-published" type="checkbox" ${p.published ? "checked" : ""}> Publish these terms to clients</label><p>Empty prices remain “contact your administrator.” Saving terms does not create invoices, charge cards or expand storage quotas.</p></div>`;
}
function readPlanForm() {
  const number = (id, multiplier) => {
    const value = $(id).value.trim();
    return value === "" ? null : Math.round(Number(value) * multiplier);
  };
  return {
    published: $("#plan-published").checked,
    downloadLimitBytes: number("#plan-download", 1e12),
    downloadMode: $("#plan-mode").value,
    downloadOverageCentsPerGB: number("#plan-download-rate", 100),
    storageUpgradeCentsPerTB: number("#plan-storage-rate", 100),
    additionalServices: $("#plan-services").value.trim(),
  };
}
function renderSecurity() {
  const s = data.security,
    archive = s.archive,
    last = s.maintenance.lastSuccess;
  $("#pagebody").innerHTML =
    `<div class="card section-panel"><div class="cardhead"><h2>Service activation checklist</h2></div><div class="panel-content"><p>Provider approvals and technical verification are reviewed separately. Recording an approval requires supporting evidence.</p>${(s.activation?.providerApprovals || []).map((p) => `<div class="row"><span>${esc(p.label)}</span><strong>${p.confirmed ? "Recorded" : "Awaiting verification"}</strong></div>`).join("")}<p>Cloud portal checks: ${s.technicalReady ? "Current" : "Incomplete"}. Portal approval: ${s.activation?.launchComplete ? "Recorded" : "Pending"}.</p><p>Practice uploader onboarding: ${s.practiceOnboarding?.ready ? "Verified" : "Pending endpoint review and two-night pilot"}. This is tracked separately and does not block portal approval. Scheduled practice uploads still require onboarding verification.</p></div></div><div class="card section-panel"><div class="cardhead"><h2>Recovery backups and readiness</h2></div><div class="panel-content"><p>Metadata backups: ${s.backups?.configured ? "Configured" : "Needs setup"} / 30-day retention</p><p>Last verified: ${s.backups?.lastSuccess ? date(s.backups.lastSuccess.verified) : "Not yet verified"}<br>Next expected scheduled run: ${s.backups?.nextExpected ? date(s.backups.nextExpected) : "Awaiting first scheduled backup"}<br>Monthly restore review: ${s.backups?.restoreReviewDue ? "Due" : "Current"}</p><p>Production authorization: ${config.demo ? "Preview only" : config.ready ? "Provider review gates satisfied" : "Pending provider review"}. Technical readiness: ${s.technicalReady ? "Checks current" : "Incomplete"}.</p><button data-action="securitybackup">Run metadata backup</button> <button data-action="securitynotify">Send test alert</button> <button data-action="securityevidence">Record acceptance evidence</button><p>Emails accepted by the delivery service are not proof of inbox receipt.</p>${(
      s.notifications?.deliveries || []
    )
      .slice(0, 5)
      .map(
        (d) =>
          `<p>Notification ${date(d.created)} / ${esc(d.status)} / ${d.attempts} attempt(s)</p>`,
      )
      .join(
        "",
      )}<p>${(s.evidence || []).map((e) => esc(e.id) + ": " + date(e.created)).join(" / ")}</p></div></div><div class="notice">${s.synthetic ? "Synthetic test environment. No production assurance is implied." : s.technicalApproval ? "Technical review is current. Production authorization remains separate." : "Technical approval remains pending until all required live checks and recovery reviews are completed."}</div><div class="stats">${metric("Protected archive", archive.configured ? (archive.synthetic ? "Local test only" : "Configured") : "Needs setup", "365-day COMPLIANCE retention; verified per archived object")}${metric("Scheduled maintenance", s.maintenance.configured ? "Secret configured" : "Secret missing", last ? "Last completed " + date(last.at) : "No completed maintenance run")}${metric("Open alerts", String(s.alerts.filter((a) => a.status === "open").length), "Acknowledgment records a review; it does not fix the underlying problem")}${metric("Access review", s.accessReview ? date(s.accessReview.at) : "Not recorded", "Review accounts and practice roles monthly")}</div><div class="detailgrid"><div class="card section-panel"><div class="cardhead"><h2>Verification and maintenance</h2></div><div class="panel-content"><p>Archive queued logs, verify their chains and locked copies, and check database transport, uploader health and stalled transfers.</p><button class="primary" data-action="securitymaintenance">Run maintenance & archive</button><p>Run a synthetic 17 MiB upload/download/restore test in the selected workspace. Only the generated canary is cleaned up; client files are untouched.</p><button data-action="securitystorage" ${tenant ? "" : "disabled"}>Test selected workspace storage</button><p>Live archive setup uses the approved dedicated 365-day locked bucket. Missing credential permissions are reported, not bypassed.</p>${s.maintenance.lastFailure ? `<div class="notice">Last maintenance failure: ${esc(s.maintenance.lastFailure.message)} (${date(s.maintenance.lastFailure.at)})</div>` : ""}${s.maintenance.stale ? '<div class="notice">Maintenance evidence is missing or older than two hours. Automatic archival is not verified.</div>' : ""}</div></div><div class="card section-panel"><div class="cardhead"><h2>Access and recovery</h2></div><div class="panel-content"><button data-action="securityaccess">Review administrator and member access</button><p>Protected metadata backup and isolated restore tools are included in the operator package. Recovery key custody and independent recovery evidence must be reviewed separately.</p><ul>${s.remaining.map((v) => `<li>${esc(v)}</li>`).join("")}</ul><p>Alerts are retained in this dashboard. Email delivery: ${s.notifications?.configured ? "configured; confirm inbox receipt separately" : "needs setup"}.</p></div></div></div><div class="card section"><div class="cardhead"><h2>Security alerts</h2></div><div class="panel-content">${s.alerts.length ? s.alerts.map((a) => `<div class="row"><div><strong>${esc(a.code.replaceAll("_", " "))}</strong><p>${esc(a.severity)} · ${esc(a.status)} · ${a.occurrences} occurrence(s) · ${date(a.last_seen)}</p></div>${["open", "acknowledged"].includes(a.status) ? `<div class="actions">${a.status === "open" ? `<button data-securityack="${a.id}">Acknowledge</button>` : ""}<button data-securityresolve="${a.id}">Resolve after verification</button></div>` : ""}</div>`).join("") : "<p>No alerts recorded. This alone does not establish a completed security review.</p>"}</div></div><div class="card section"><div class="cardhead"><h2>Verification history</h2></div><div class="panel-content">${
      s.checks
        .slice(0, 20)
        .map(
          (c) =>
            `<details><summary>${esc(c.kind)} · ${esc(c.status)} · ${date(c.created)}</summary><pre>${esc(JSON.stringify(c.result, null, 2))}</pre></details>`,
        )
        .join("") || "<p>No verification runs yet.</p>"
    }</div></div><div class="card section"><div class="cardhead"><h2>Recent security events</h2><button data-action="securityexport">Export these events</button></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Event</th><th>Severity / status</th><th>Route</th><th>Request ID</th></tr></thead><tbody>${s.events.map((e) => `<tr><td>${date(e.created)}</td><td>${esc(e.event)}</td><td>${esc(e.severity)} / ${e.status}</td><td>${esc(e.method)} ${esc(e.route)}</td><td>${esc(e.request_id)}</td></tr>`).join("")}</tbody></table></div></div>`;
}
function renderMspSettings() {
  const m = data.mspSettings;
  $("#pagebody").innerHTML =
    `<div class="detailgrid"><div><div class="card section-panel"><div class="cardhead"><h2>Your administrator account</h2></div><div class="panel-content"><h3>${esc(m.email)}</h3><p>Account security and your own storage are independent of the client selected in the sidebar.</p><button data-action="accountsecurity">Account security & MFA</button></div></div><div class="card section section-panel"><div class="cardhead"><h2>My private workspace</h2></div><div class="panel-content">${m.internalWorkspace ? `<h3>${esc(m.internalWorkspace.name)}</h3><p>${esc(m.internalWorkspace.status)}</p><button class="primary" data-internal="${m.internalWorkspace.id}">Open my workspace</button>${m.internalWorkspace.status !== "active" ? `<button data-storagesetup="${m.internalWorkspace.id}">Resume storage setup</button>` : ""}` : '<p>Create a dedicated private bucket for your own MSP files. Practice members cannot access it.</p><button class="primary" data-action="newinternal">Create my workspace</button>'}</div></div><div class="card section section-panel"><div class="cardhead"><h2>Provider cost reference</h2></div><div class="panel-content"><p>Public B2 base storage pricing checked November 19, 2026: $6.95/TB/month. Free egress is generally 3× actual average monthly account storage, then $0.01/GB. Upload ingress is free; hosting and special API/service charges may still apply.</p><p>These are supplier terms, not your customer plan. Retained versions consume storage; your 4 TB client allowance is a portal limit, not preallocated capacity.</p><a href="https://www.backblaze.com/cloud-storage/pricing" target="_blank" rel="noopener noreferrer">Current provider pricing</a></div></div></div><div class="card section-panel"><div class="cardhead"><h2>Default client plan</h2></div><div class="panel-content"><p>Applies to client workspaces without an individual override. The current storage allowance remains 4 TB per practice.</p>${planFields(m.policy)}<button class="primary" data-action="savedefaultplan">Save default plan</button></div></div></div>`;
}
function renderPlan() {
  const t = user.tenants.find((t) => t.id === tenant),
    r = data.plan,
    p = r.policy,
    m = r.meter,
    remaining =
      p.published && p.downloadLimitBytes !== null
        ? Math.max(
            0,
            p.downloadLimitBytes - m.downloadedBytes - m.reservedDownloadBytes,
          )
        : null;
  $("#pagebody").innerHTML =
    `<div class="stats">${metric("Storage allowance", bytes(r.storageLimitBytes), bytes(t.used || 0) + " used, including trash and upload reservations")}${metric("Maximum per file", fileLimit(r.maxFileBytes), config.transferLimits?.pilot ? "Current pilot limit" : "Configured file limit")}${metric("Downloaded this month", bytes(m.downloadedBytes), m.period + " UTC · tracked since " + date(m.trackingSince))}${metric("Included monthly downloads", p.published && p.downloadLimitBytes !== null ? bytes(p.downloadLimitBytes) : "Not published", remaining === null ? "Contact your storage administrator" : bytes(remaining) + " currently available")}</div><div class="detailgrid"><div class="card section-panel"><div class="cardhead"><h2>${t.kind === "internal" ? "Private workspace usage" : "Allowances and additional services"}</h2>${user.msp && t.kind !== "internal" ? '<button data-action="editworkspaceplan">Edit client plan</button>' : ""}</div><div class="panel-content">${p.published ? `<div class="row"><span>Download overage</span><strong>${p.downloadOverageCentsPerGB === null ? "By agreement" : dollars(p.downloadOverageCentsPerGB) + " / GB"}</strong></div><div class="row"><span>Additional storage</span><strong>${p.storageUpgradeCentsPerTB === null ? "By agreement" : dollars(p.storageUpgradeCentsPerTB) + " / TB/month"}</strong></div><p>${p.downloadMode === "block" ? "Further downloads are blocked when the monthly allowance is reached." : "Downloads above the included amount may require additional service charges under your published agreement."}</p><p class="plan-terms">${esc(p.additionalServices)}</p>` : "<p>Transfer allowances and additional-service prices have not been published. Contact your administrator before arranging bulk restores, migrations or additional capacity.</p>"}<p>The portal does not automatically invoice or charge for overages.</p></div></div><div class="card section-panel"><div class="cardhead"><h2>How usage is counted</h2></div><div class="panel-content"><ul><li>Files in trash and space reserved for unfinished uploads count toward storage.</li><li>Range downloads, repeated downloads and transfer retries can add traffic.</li><li>Uploads this month: ${bytes(m.uploadedBytes)}. In-progress download reservations: ${bytes(m.reservedDownloadBytes)}.</li><li>Usage covers portal-authorized transfers, not activity outside this service.</li><li>Browser upload resume lasts for the current page session; the scheduled uploader keeps its own resume state.</li></ul>${config.transferLimits?.direct ? '<div class="notice">Large files transfer using short-lived links. Upload usage counts confirmed parts, excluding repeated attempts. Downloads count the full file when a link is issued; an unused link still counts. Links expire after 60 seconds but may be reused until then. Download controls limit new link issuance, not exact network traffic. Actual provider billing may differ.</div>' : ""}<p>Request approval before additional storage, assisted restoration, extended retention or migration work.</p></div></div></div>`;
}
function renderFiles() {
  const folders = [...new Set(data.files.map((f) => f.folder || "General"))];
  $("#pagebody").innerHTML =
    `${trash ? "" : drop()}<div class="card"><div class="toolbar"><div class="search">${icon("search")}<input id="search" aria-label="Search files" placeholder="Search files or folders…" value="${esc(query)}"></div><div class="filters"><select id="folderfilter" aria-label="Filter by folder"><option>All folders</option>${folders.map((f) => `<option ${f === folder ? "selected" : ""}>${esc(f)}</option>`).join("")}</select><div class="pilltabs"><button id="allfiles" class="${!trash ? "selected" : ""}">Files</button><button id="trashfiles" class="${trash ? "selected" : ""}">Trash</button></div></div></div><div id="filelist"></div></div>`;
  const update = () => {
    $("#filelist").innerHTML = filetable(
      data.files.filter(
        (f) =>
          (folder === "All folders" || f.folder === folder) &&
          (f.name + " " + f.folder).toLowerCase().includes(query.toLowerCase()),
      ),
    );
  };
  update();
  $("#search").oninput = (e) => {
    query = e.target.value;
    update();
  };
  $("#folderfilter").onchange = (e) => {
    folder = e.target.value;
    update();
  };
  $("#allfiles").onclick = () => {
    trash = false;
    navigate("Files");
  };
  $("#trashfiles").onclick = () => {
    trash = true;
    folder = "All folders";
    navigate("Files");
  };
}
function scheduleText(p) {
  const s = p.schedule;
  return s.kind === "interval"
    ? `Every ${s.minutes === 60 ? "hour" : s.minutes === 240 ? "4 hours" : "15 minutes"}`
    : `${s.time} · ${s.days.map((d) => ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][d]).join(", ")} · computer local time`;
}
function renderUploaders() {
  const devices = data.devices;
  $("#pagebody").innerHTML =
    `<div class="banner">${icon("upload")}<div><h3>From their computer. Into their vault.</h3><p>New and changed files upload automatically. Originals stay where they are.</p></div><span class="badge">One-way uploads</span></div><div class="card"><div class="cardhead"><h2>Practice uploaders</h2><span style="font-size:11px;color:#91a196">${devices.filter((d) => !d.revoked).length} enrolled or pending</span></div>${
      devices.length
        ? devices
            .map((d) => {
              const online =
                d.last_seen &&
                Date.now() - new Date(d.last_seen).getTime() < 120000;
              const state = d.revoked
                ? "Revoked"
                : d.credential_expires && d.credential_expires < Date.now()
                  ? "Credential expired"
                  : !d.enrolled
                    ? "Awaiting setup"
                    : !d.last_seen
                      ? "Awaiting first contact"
                      : d.paused
                        ? "Paused"
                        : !online
                          ? "Offline"
                          : d.status === "uploading"
                            ? "Uploading"
                            : d.status === "error"
                              ? "Needs attention"
                              : "Connected";
              return `<div class="row"><div class="automation"><span class="automationicon">${icon("upload")}</span><div><h3>${esc(d.label)} <span class="badge ${["Offline", "Needs attention"].includes(state) ? "amber" : ""}">${state}</span></h3><p>${esc(scheduleText(d.policy))} → ${esc(d.policy.folder)}</p><p>Last contact: ${d.last_seen ? date(d.last_seen) : "Not yet"} · Last successful run: ${d.last_success ? date(d.last_success) : "Not yet"}</p>${d.credential_expires ? `<p>Credential expires: ${date(d.credential_expires)}</p>` : ""}</div></div><div class="actions">${!d.revoked ? `${!d.enrolled ? `<button data-enrollment="${d.id}" style="font-size:11px">New setup code</button>` : `<button data-rundevice="${d.id}" ${d.paused ? "disabled" : ""} style="font-size:11px">${icon("play")}Run on next contact</button>`}<button title="Edit schedule" data-editdevice="${d.id}">${icon("gear")}</button><button title="${d.paused ? "Resume" : "Pause"} uploader" data-pausedevice="${d.id}">${icon(d.paused ? "play" : "pause")}</button><button title="Revoke uploader" class="danger" data-revokedevice="${d.id}">${icon("close")}</button>` : ""}<button title="Run history" data-deviceruns="${d.id}">${icon("activity")}</button></div></div>`;
            })
            .join("")
        : empty(
            "Put uploads on autopilot",
            "Enroll a practice computer to begin scheduled uploads.",
          )
    }</div><div class="detailgrid section"><div class="card quickcard"><h2>Set it up once. Let it upload.</h2><p style="margin-top:12px">1. Download the current Windows installer from Add uploader.</p><p>2. Configure the uploader here, then get a fresh enrollment code.</p><p>3. Run the installer on the practice computer, select local folders and enter the code. It uploads while awake and online.</p><button data-action="downloaduploader">${icon("download")}Download current installer</button> <button data-action="uploaderhelp">View setup details ${icon("arrow")}</button></div><div class="card quickcard"><h2>You stay in control.</h2><p style="margin-top:12px">Pause or revoke a device at any time. Interrupted uploads resume from completed parts.</p><p>Local and cloud files are never deleted by this uploader. A changed file is stored as a new object and counts toward your 4 TB allowance.</p><p>Schedule changes apply on the next device contact. Folder access must be changed locally by your administrator.</p></div></div>`;
}
function deviceFields(d) {
  const p = d?.policy || {
    folder: "Pilot test files",
    schedule: { kind: "daily", time: "21:00", days: [0, 1, 2, 3, 4, 5, 6] },
  };
  return `${!d ? field("Computer or uploader name", "devicelabel") : ""}${field("Cloud destination folder", "devicefolder", p.folder)}<label class="field">Upload schedule<select id="deviceschedule"><option value="15" ${p.schedule.minutes === 15 ? "selected" : ""}>Every 15 minutes</option><option value="60" ${p.schedule.minutes === 60 ? "selected" : ""}>Hourly</option><option value="240" ${p.schedule.minutes === 240 ? "selected" : ""}>Every 4 hours</option><option value="daily" ${p.schedule.kind === "daily" ? "selected" : ""}>Selected days at a local time</option></select></label>${field("Daily time (practice computer local time)", "devicetime", p.schedule.time || "21:00", "time")}<label class="field">Days</label><div class="actions">${["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((day, i) => `<label style="font-size:11px"><input type="checkbox" name="deviceday" value="${i}" ${(p.schedule.days || [0, 1, 2, 3, 4]).includes(i) ? "checked" : ""}>${day}</label>`).join("")}</div><p style="margin-top:14px">The computer must be awake and online. Local source folders are selected during installation.</p>`;
}
function devicePolicy() {
  const value = $("#deviceschedule").value;
  return {
    folder: $("#devicefolder").value.trim(),
    schedule:
      value === "daily"
        ? {
            kind: "daily",
            time: $("#devicetime").value,
            days: [
              ...document.querySelectorAll('[name="deviceday"]:checked'),
            ].map((e) => Number(e.value)),
          }
        : { kind: "interval", minutes: Number(value) },
  };
}
async function downloadUploader(release) {
  if (config.demo || preview) { toast("Preview only: no installer was downloaded"); return; }
  const grant = await api(base() + "/uploader-release/download", "POST", {});
  if (release && grant.version !== release.version) throw Error("A new installer was released. Close this window and open Add uploader again.");
  const anchor = document.createElement("a");
  anchor.href = grant.url;
  anchor.rel = "noreferrer";
  anchor.referrerPolicy = "no-referrer";
  document.body.append(anchor); anchor.click(); anchor.remove();
}
async function uploaderSetup() {
  const release = await api(base() + "/uploader-release");
  if (!release.configured) throw Error(release.message || "Installer is not available yet");
  modal("1. Download the Windows installer", `<p>Set up this practice computer directly from the portal.</p><p><strong>Windows x64 · v${esc(release.version)}</strong> · ${bytes(release.bytes)}</p><p>Pilot release · unsigned. Extract the entire ZIP, then run Streamlined-Vault-Pilot-Setup.exe as administrator. The package includes its Python runtime.</p><button id="downloadinstaller" class="primary">${icon("download")}Download Windows installer (.zip)</button><p id="installer-download-state" role="status">Download the installer, then continue to get your enrollment code.</p><details><summary>Verify your download</summary><p class="release-checksum">SHA-256: ${esc(release.sha256)}</p></details>`, async () => {
    modal("2. Configure your uploader", deviceFields(), async () => {
      const r = await api(base() + "/devices", "POST", {label:$("#devicelabel").value.trim(),...devicePolicy()});
      $("#modal").close(); await navigate("Uploaders"); enrollmentDialog(r,release);
    }, "Create enrollment code");
  }, "Continue to enrollment");
  $("#confirm").disabled = true;
  $("#downloadinstaller").onclick = async () => {
    const button = $("#downloadinstaller"); button.disabled = true;
    try {
      await downloadUploader(release);
      $("#installer-download-state").textContent = config.demo || preview ? "Preview: installer download simulated. Continue to explore enrollment." : "Download requested. Once it finishes, continue to create your 15-minute code.";
      $("#confirm").disabled = false;
    } catch(e) { $("#modal .formerror").textContent=e.message; }
    finally { button.disabled=false; }
  };
}
function enrollmentDialog(r, release) {
  modal("3. Connect your practice computer", `<p>${config.demo ? "Preview code: cannot enroll a real computer." : "Your one-time enrollment code expires in 15 minutes."}</p><div class="tokenbox">${esc(r.code)}</div><button id="copyenrollment">Copy code</button><ol><li>Extract the installer ZIP and run Streamlined-Vault-Pilot-Setup.exe as administrator.</li><li>For the pilot, select a new empty local folder for non-patient test files.</li><li>Paste this code into the installer. Keep the computer awake and connected for scheduled uploads.</li></ol><p>Need the package again? <button data-action="downloaduploader">Download current installer</button></p>${release ? `<p>Installer v${esc(release.version)} · Windows x64 · unsigned pilot</p>` : ""}`, null);
  $("#copyenrollment").onclick = async () => { try { await navigator.clipboard.writeText(r.code); toast("Enrollment code copied"); } catch { toast("Select and copy the code above"); } };
  $("#cancel").textContent = "Done";
}

function renderTransfers() {
  $("#pagebody").innerHTML =
    `<div class="card"><div class="cardhead"><h2>Upload queue</h2><span style="font-size:11px;color:#98a6ae">This browser session</span></div><div id="transferlist">${transfers.length ? transfers.map((t) => `<div class="transfer"><span class="fileicon">${icon("file")}</span><div class="transferbody"><h3>${esc(t.file.name)}</h3><div class="progress"><i style="width:${t.percent}%"></i></div><p>${esc(t.status)} · ${t.percent}% · ${bytes(t.file.size)}${t.message ? " · " + esc(t.message) : ""}</p></div><div class="actions">${t.status === "Uploading" ? `<button data-pause="${t.local}">${icon("pause")}Pause</button>` : ["Paused", "Failed"].includes(t.status) ? `<button data-resume="${t.local}">${icon("play")}Resume</button><button data-cancelupload="${t.local}" title="Cancel upload">${icon("close")}</button>` : icon("check")}</div></div>`).join("") : empty("No transfers yet", "Choose files in your workspace to start uploading.")}</div></div>`;
}
function renderAudit() {
  $("#pagebody").innerHTML =
    `<div class="card"><div class="cardhead"><h2>Workspace activity</h2><span style="font-size:10px;color:#8f9ca7">Most recent 500 events</span></div><div class="tablewrap"><table><thead><tr><th>Event</th><th>Actor</th><th>Time</th><th>Reference</th></tr></thead><tbody>${data.audit.map((e) => `<tr><td>${esc(e.action)}</td><td>${esc(e.actor)}</td><td>${date(e.created)}</td><td style="color:#9ba6af;font-family:monospace;font-size:9px">${esc(e.resource?.slice(0, 12) || "—")}</td></tr>`).join("")}</tbody></table></div>${!data.audit.length ? empty("A fresh start", "Activity will appear as your team uses the workspace.") : ""}</div>`;
}
let invitationRefreshTimer;
function renderTeam() {
  clearTimeout(invitationRefreshTimer);
  const cooldowns = data.members.map(m => m.invitation?.retryAfter || 0).filter(ms => ms > 0);
  if (cooldowns.length && !preview) invitationRefreshTimer = setTimeout(() => {
    if (page === "Team & access" && !$("#modal").open) navigate(page);
  }, Math.min(...cooldowns) + 100);
  $("#pagebody").innerHTML =
    `<div class="card"><div class="cardhead"><h2>Users for ${esc(user.tenants.find((t) => t.id === tenant)?.name)}</h2><button class="primary" data-action="invite">${icon("plus")}Add user</button></div>${data.members.length ? data.members.map((m) => `<div class="row"><div class="automation"><span class="avatar">${esc(m.email.slice(0, 2).toUpperCase())}</span><div><h3>${esc(m.email)}</h3><p>${{ admin: "Manage practice files, members, and uploaders", editor: "Upload, download, rename, and restore files", viewer: "Browse and download files", uploader: "Upload files only" }[m.role]}</p></div></div><div class="actions"><span class="tag">${esc(m.role)}</span>${user.msp ? `<span class="invite-status">${esc(({not_invited:"Not invited",accepted:m.invitation?.kind === "instructions" ? "Instructions sent" : "Invitation sent",ready:"Account ready",expired:"Expired",failed:"Send failed",revoked:"Revoked",revocation_pending:"Revocation pending",sending:"Sending"})[m.invitation?.status || "not_invited"] || "Not invited")}${m.invitation?.lastSent ? `<small>${date(m.invitation.lastSent)}</small>` : ""}</span><button data-inviteuser="${esc(m.email)}" ${m.invitation?.retryAfter > 0 ? "disabled" : ""}>${m.invitation?.status === "ready" ? "Send sign-in instructions" : m.invitation?.lastSent ? "Resend email" : "Send invitation"}</button>` : ""}${m.email !== user.email ? `<button data-remove="${esc(m.email)}" class="quiet" title="Remove access">${icon("close")}</button>` : ""}</div></div>`).join("") : empty("No users assigned to this practice", "Click Add user and enter the exact email used to sign in. Creating an account alone does not grant practice access.")}</div><div class="card section quickcard"><h2>Simple access, clear responsibilities.</h2><p style="margin-top:10px">This list shows users assigned to this practice, not everyone who has signed up. Click Add user, enter their exact sign-in email and choose a role. Then use Send invitation to email enrollment instructions. Existing account holders receive sign-in instructions. Only MSP administrators can send these emails. Provider acceptance does not confirm inbox delivery.</p></div>`;
}
function renderClients() {
  $("#pagebody").innerHTML = `<div class="clientgrid">${user.tenants
    .filter((t) => t.kind !== "internal")
    .map(
      (t) =>
        `<div class="card clientcard"><span class="clienticon">${icon("building")}</span><h2>${esc(t.name)}</h2><p>Client workspace · 4 TB plan</p><div class="storage-summary"><strong>${t.storage?.kind === "dedicated" ? "Dedicated private bucket" : "Original shared storage"}</strong><span>${esc(t.storage?.bucket || "Not assigned")}</span><small>${esc(t.storage?.region || "")} · ${esc(t.storage?.status || "ready")}</small></div><div class="storagebar"><i style="width:${(t.used / t.quota) * 100}%"></i></div><div class="storagetext"><span>${bytes(t.used)} used</span><span>${t.status === "active" ? "Active" : t.status === "suspended" ? "Suspended" : "Storage setup needed"}</span></div><button data-client="${t.id}">Open workspace</button><button data-manageusers="${t.id}">${icon("users")}Manage users</button>${t.storage?.status === "error" || t.storage?.status === "provisioning" ? `<button data-storagesetup="${t.id}">Resume storage setup</button>` : t.storage?.kind !== "dedicated" && t.used === 0 ? `<button data-storagesetup="${t.id}">Assign dedicated storage</button>` : ""}</div>`,
    )
    .join(
      "",
    )}</div><div class="card section quickcard"><h2>Dedicated storage for each practice.</h2><p>New workspaces use their own private bucket and bucket-restricted credential. File transfers and scheduled uploaders follow the workspace assignment. Existing files keep their original storage location.</p></div>`;
}
function storageFields(existing) {
  const c = user.storageCapabilities || { create: true, connect: true },
    mode = existing?.mode || (c.create ? "create" : "connect");
  return `<div class="storage-options"><label class="field">Workspace storage<select id="storagemode"><option value="create" ${mode === "create" ? "selected" : ""}>Create a new private bucket</option><option value="connect" ${mode === "connect" ? "selected" : ""}>Connect an existing private bucket</option></select></label><p id="storage-create-help">A private encrypted bucket and a restricted file credential will be created for this practice. The bucket name uses an opaque workspace ID.</p><div id="storage-connect-fields">${field("Bucket name", "storagebucket", existing?.bucket || "")}${field("S3 endpoint", "storageendpoint", existing?.endpoint || "", "url")}${field("Restricted key ID", "storagekeyid")}${field("Application key", "storagekey", "", "password")}<p>The key must be restricted to this private, AES256-encrypted bucket. Existing bucket contents are not automatically imported.</p></div>${!c.create || !c.connect ? `<div class="notice">${c.metadataPending ? "Dedicated storage is waiting for the Neon metadata migration so workspace assignments survive server restarts." : !c.connect ? "Server setup required: configure the credential-encryption key before connecting storage." : !c.create ? "Automatic creation needs the server provisioning credential. You can connect an existing bucket now." : ""}</div>` : ""}<p class="storage-preview">${config.demo ? "Synthetic preview only. No real bucket or credential is created." : "Storage credentials are encrypted on the server and never shown to practice users."}</p></div>`;
}
function wireStorageFields(existing) {
  const mode = $("#storagemode");
  if (existing?.kind === "dedicated") {
    mode.value = existing.mode;
    mode.disabled = true;
  }
  const update = () => {
    const connect = mode.value === "connect";
    $("#storage-connect-fields").classList.toggle("hidden", !connect);
    $("#storage-create-help").classList.toggle("hidden", connect);
    const caps = user.storageCapabilities || { create: true, connect: true };
    $("#confirm").disabled = !(connect ? caps.connect : caps.create);
  };
  mode.onchange = update;
  update();
  $("#storagekey").autocomplete = "off";
  $("#storagekeyid").autocomplete = "off";
  $("#modal").addEventListener(
    "close",
    () => {
      if ($("#storagekey")) $("#storagekey").value = "";
    },
    { once: true },
  );
}
function storageInput() {
  return $("#storagemode").value === "create"
    ? { mode: "create" }
    : {
        mode: "connect",
        bucket: $("#storagebucket").value.trim(),
        endpoint: $("#storageendpoint").value.trim(),
        keyId: $("#storagekeyid").value.trim(),
        applicationKey: $("#storagekey").value.trim(),
      };
}
function workspaceDialog(existing, kind = "client") {
  const requestId = crypto.randomUUID();
  modal(
    existing
      ? "Assign workspace storage"
      : kind === "internal"
        ? "Create my MSP workspace"
        : "Add a client practice",
    `${existing ? `<p>Dedicated storage for ${esc(existing.name)}. Storage cannot be changed after files are uploaded.</p>` : `<p>Create a workspace with a dedicated bucket and a 4 TB allowance.</p>${field(kind === "internal" ? "Workspace name" : "Practice name", "clientname", kind === "internal" ? "MSP workspace" : "")}`}${storageFields(existing?.storage)}`,
    async () => {
      const name = existing?.name || $("#clientname").value.trim();
      if (name.length < 2) throw Error("Enter a practice name");
      const storage = storageInput();
      if (
        storage.mode === "connect" &&
        !config.demo &&
        (!storage.bucket ||
          !storage.endpoint ||
          !storage.keyId ||
          !storage.applicationKey)
      )
        throw Error("Complete the bucket and restricted-key fields");
      const t = existing
        ? await api(`/api/tenants/${existing.id}/storage`, "POST", { storage })
        : await api("/api/tenants", "POST", { name, storage, requestId, kind });
      await refresh();
      tenant = existing?.id || t.id;
      $("#modal").close();
      await navigate(
        kind === "internal" ? "MSP settings" : "Client workspaces",
      );
      toast(
        config.demo
          ? "Preview workspace created; no cloud storage provisioned"
          : "Workspace has dedicated private storage",
      );
    },
    existing ? "Connect storage" : "Create workspace",
  );
  wireStorageFields(existing?.storage);
}

function renderSettings() {
  const t = user.tenants.find((t) => t.id === tenant);
  $("#pagebody").innerHTML =
    `<div class="detailgrid"><div class="card"><div class="cardhead"><h2>Workspace details</h2><button data-nav="Plan & usage">Plan & usage</button></div>${user.msp ? `<div class="card section-panel"><div class="panel-content"><h3>Large browser transfers</h3><p>Allow this portal’s HTTPS origin to transfer file parts directly into the private bucket. This does not make files public.</p><p>Browser setup: ${t.browserTransfers?.configured ? "Configured" : "Not yet recorded for this website and bucket"}. Production authorization: ${config.demo ? "Preview only" : config.ready ? "Provider review gates satisfied" : "Pending review"}.</p><button data-browsertransfers="${tenant}">Configure browser transfers</button></div></div>` : ""}${[
      ["Workspace", t.name],
      ["Storage allowance", "4 TB · 4,000,000,000,000 bytes"],
      [
        "Usage",
        bytes(t.used) + " · includes trash and in-progress reservations",
      ],
      ["Your role", t.role],
      [
        "Storage",
        t.storage?.kind === "dedicated"
          ? "Dedicated private storage"
          : "Original shared storage",
      ],
      ...(user.msp
        ? [
            ["Assigned bucket", t.storage?.bucket || "Not assigned"],
            ["Storage status", t.storage?.status || "ready"],
          ]
        : []),
      ["File delivery", "Through the branded portal"],
      [
        "Identity",
        config.demo
          ? "Preview session"
          : "Organization sign-in with MFA assurance",
      ],
    ]
      .map(
        ([l, v]) =>
          `<div class="row"><span style="font-size:11px;color:#8999a5">${l}</span><strong style="font-size:11px;font-weight:500">${esc(v)}</strong></div>`,
      )
      .join(
        "",
      )}</div><div class="card"><div class="cardhead"><h2>Protection and recovery</h2></div>${user.msp && t.kind !== "internal" ? '<div class="capability"><button data-action="editworkspaceplan">Edit this client’s plan</button></div>' : ""}${[
      ["Private access", "File requests are scoped to the signed-in practice."],
      [
        "Recoverable deletion",
        "Files moved to trash remain recoverable and count toward storage. No automatic permanent deletion.",
      ],
      [
        "Transfer integrity",
        "Each uploaded part is checked, followed by stored-size verification.",
      ],
      ["Activity history", "File and administrative actions are recorded."],
      [
        "Production status",
        config.demo
          ? "Preview only. Security and compliance controls require production configuration."
          : "Operator review and contractual requirements must be completed before patient data.",
      ],
    ]
      .map(
        ([l, v]) =>
          `<div class="capability"><strong>${l}</strong><p>${v}</p></div>`,
      )
      .join("")}</div></div>`;
}
function wireDrop() {
  const zone = $("#dropzone");
  if (!zone) return;
  zone.onclick = () => uploadDialog();
  zone.onkeydown = (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      uploadDialog();
    }
  };
  zone.ondragover = (e) => {
    e.preventDefault();
    zone.classList.add("drag");
  };
  zone.ondragleave = () => zone.classList.remove("drag");
  zone.ondrop = (e) => {
    e.preventDefault();
    zone.classList.remove("drag");
    uploadDialog([...e.dataTransfer.files]);
  };
}
function uploadDialog(selected = []) {
  modal(
    "A new home for your files.",
    `<p>${config.demo ? "Select synthetic files only." : "Choose files to upload to this practice."}</p><p>Maximum per file: <strong>${fileLimit(config.transferLimits?.maxFileBytes || 50 * 1024 ** 3)}</strong>. <button data-nav="Plan & usage">View plan limits</button></p>${field("Destination folder", "uploadfolder", folder === "All folders" ? "General" : folder)}<button id="browsefiles" style="width:100%">${icon("upload")}Choose files</button><p id="selectedfiles" style="margin-top:12px">${selected.length ? selected.length + " file(s) selected" : "No files selected"}</p>${config.demo ? "<p>Synthetic preview: use small files without patient data.</p>" : ""}`,
    async () => {
      if (!selected.length) throw Error("Choose at least one file");
      const maximum = config.transferLimits?.maxFileBytes || 50 * 1024 ** 3;
      if (selected.some((f) => f.size > maximum))
        throw Error(
          "A selected file exceeds the current " +
            fileLimit(maximum) +
            " per-file limit.",
        );
      const target = tenant,
        dest = $("#uploadfolder").value.trim() || "General";
      $("#modal").close();
      for (const file of selected) {
        const t = {
          local: crypto.randomUUID(),
          file,
          tenant: target,
          folder: dest,
          status: "Queued",
          percent: 0,
          parts: new Set(),
        };
        transfers.unshift(t);
        processUpload(t);
      }
      await navigate("Transfers");
    },
    "Start upload",
  );
  $("#browsefiles").onclick = () => {
    const picker = $("#filepicker");
    picker.value = "";
    picker.onchange = () => {
      selected = [...picker.files];
      $("#selectedfiles").textContent = `${selected.length} file(s) selected`;
    };
    picker.click();
  };
}
async function processUpload(t) {
  if (t.running) return;
  t.running = true;
  t.pause = false;
  t.status = "Uploading";
  t.message = "";
  try {
    if (!t.id) {
      const u = await api(`/api/tenants/${t.tenant}/uploads`, "POST", {
        name: t.file.name,
        folder: t.folder,
        size: t.file.size,
        requestId: t.local,
        browser: true,
      });
      t.id = u.id;
      t.partSize = u.partSize;
      t.transport = u.transport;
    }
    for (
      let offset = 0, n = 1;
      offset < t.file.size;
      offset += t.partSize, n++
    ) {
      if (t.pause) {
        t.status = "Paused";
        return;
      }
      if (t.parts.has(n)) continue;
      const b = t.file.slice(
        offset,
        Math.min(offset + t.partSize, t.file.size),
      );
      let failure;
      for (let retry = 0; retry < 3; retry++) {
        try {
          if (t.transport === "direct") {
            const md5 = btoa(
              SparkMD5.ArrayBuffer.hash(await b.arrayBuffer(), true),
            );
            const grant = await api(
              `/api/tenants/${t.tenant}/uploads/${t.id}/parts/${n}/sign`,
              "POST",
              { md5 },
            );
            const response = await fetch(grant.url, {
              method: "PUT",
              body: b,
              headers: grant.headers,
              credentials: "omit",
              referrerPolicy: "no-referrer",
              redirect: "error",
            });
            if (!response.ok)
              throw Error(
                "Storage transfer failed. Retry the upload or contact your administrator.",
              );
            await api(
              `/api/tenants/${t.tenant}/uploads/${t.id}/parts/${n}/ack`,
              "POST",
              {},
            );
          } else {
            await api(
              `/api/tenants/${t.tenant}/uploads/${t.id}/parts/${n}`,
              "PUT",
              b,
              true,
            );
          }
          failure = null;
          break;
        } catch (e) {
          failure = e;
          if (retry < 2)
            await new Promise((r) => setTimeout(r, 500 * (retry + 1)));
        }
      }
      if (failure) throw failure;
      t.parts.add(n);
      t.percent = Math.min(
        99,
        Math.round(
          (Math.min(offset + t.partSize, t.file.size) / t.file.size) * 100,
        ),
      );
      if (page === "Transfers") renderTransfers();
    }
    await api(`/api/tenants/${t.tenant}/uploads/${t.id}/complete`, "POST", {});
    t.status = "Completed";
    t.percent = 100;
    toast("Upload completed");
    await refresh();
  } catch (e) {
    t.status = "Failed";
    t.message = e.message;
  } finally {
    t.running = false;
    if (page === "Transfers") renderTransfers();
  }
}
async function download(fid) {
  if (preview) {
    const d = demoAPI.download(fid);
    saveBlob(d.blob, d.name);
    toast("Demo download prepared");
  } else {
    if (config.transferLimits?.direct) {
      const link = await api(
        base() + `/files/${fid}/download-link`,
        "POST",
        {},
      );
      const anchor = document.createElement("a");
      anchor.href = link.url;
      anchor.rel = "noreferrer";
      anchor.referrerPolicy = "no-referrer";
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
    } else location.assign(base() + `/files/${fid}/download`);
  }
}
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  const d = b.dataset;
  try {
    if (d.nav) {
      $("#modal").close();
      return navigate(d.nav);
    }
    if (d.client) {
      tenant = d.client;
      overviewScope = "workspace";
      return navigate("Overview");
    }
    if (d.download) return download(d.download);
    if (d.rename) {
      const f = data.files.find((f) => f.id === d.rename);
      return modal(
        "Rename file",
        field("File name", "filename", f.name),
        async () => {
          await api(base() + `/files/${f.id}`, "PATCH", {
            name: $("#filename").value.trim(),
          });
          $("#modal").close();
          await navigate(page);
        },
        "Rename",
      );
    }
    if (d.trash)
      return modal(
        "Move this file to trash?",
        "<p>The file will stay recoverable and continue to count toward storage.</p>",
        async () => {
          await api(base() + `/files/${d.trash}`, "DELETE", {});
          $("#modal").close();
          await navigate(page);
          toast("File moved to trash");
        },
        "Move to trash",
      );
    if (d.restore) {
      await api(base() + `/files/${d.restore}/restore`, "POST", {});
      await navigate(page);
      return toast("File restored");
    }
    if (d.pause) {
      transfers.find((t) => t.local === d.pause).pause = true;
      return toast("Pausing after the current part finishes");
    }
    if (d.resume) {
      processUpload(transfers.find((t) => t.local === d.resume));
      return;
    }
    if (d.cancelupload) {
      const t = transfers.find((t) => t.local === d.cancelupload);
      if (t.id)
        await api(`/api/tenants/${t.tenant}/uploads/${t.id}`, "DELETE", {});
      t.status = "Canceled";
      renderTransfers();
      return;
    }
    if (d.remove)
      return modal(
        "Remove workspace access?",
        `<p>${esc(d.remove)} will no longer have access through this practice membership.</p>`,
        async () => {
          await api(base() + "/members", "DELETE", { email: d.remove });
          $("#modal").close();
          await navigate(page);
        },
        "Remove access",
      );
    if (d.overviewscope) {
      overviewScope = d.overviewscope;
      return navigate("Overview");
    }
    if (d.action === "newinternal") return workspaceDialog(null, "internal");
    if (d.internal) {
      tenant = d.internal;
      overviewScope = "workspace";
      return navigate("Files");
    }
    if (d.action === "accountsecurity") {
      if (clerkUI) return clerkUI.openSecurity();
      return modal(
        "Account security",
        "<p>This synthetic preview has no real identity account.</p>",
        null,
      );
    }
    if (d.action === "savedefaultplan") {
      await api("/api/msp/plan", "PATCH", readPlanForm());
      await refresh();
      toast("Default client plan saved");
      return navigate("MSP settings");
    }
    if (d.action === "editworkspaceplan") {
      const r = await api(base() + "/plan");
      modal(
        "Client allowance and pricing",
        planFields(r.draft || { published: false }),
        async () => {
          await api(base() + "/plan", "PATCH", readPlanForm());
          $("#modal").close();
          await refresh();
          await navigate("Plan & usage");
        },
        "Save client plan",
      );
      return;
    }
    if (d.action === "providerinventory") {
      if (inventoryBusy) return;
      inventoryBusy = true;
      try {
        for (let n = 0; n < 30; n++) {
          data.msp.provider = await api("/api/msp/inventory", "POST", {});
          if (page !== "Overview" || overviewScope !== "all") break;
          renderMspOverview();
          if (data.msp.provider.status !== "scanning") break;
        }
      } finally {
        inventoryBusy = false;
        if (page === "Overview" && overviewScope === "all") renderMspOverview();
      }
      return;
    }
    if (d.action === "logout") {
      if (transfers.some((t) => t.running))
        throw Error("Pause or finish uploads before signing out");
      try {
        await api("/api/logout", "POST", {});
      } finally {
        user = null;
        if (clerkUI) {
          await clerkUI.signOut();
          return;
        }
        loginScreen();
      }
      return;
    }
    if (d.action === "upload") return uploadDialog();
    if (d.action === "refresh") return navigate(page);
    if (d.action === "newfolder")
      return modal(
        "Organize your next upload",
        `<p>Folders group files in your workspace. Choose a destination now, then add files to it.</p>${field("Folder name", "foldername")}`,
        () => {
          const name = $("#foldername").value.trim();
          if (!name) throw Error("Enter a folder name");
          folder = name;
          $("#modal").close();
          uploadDialog();
        },
        "Add files to folder",
      );
    if (d.action === "newclient") return workspaceDialog();
    if (d.securityack) {
      await api("/api/msp/security/acknowledge", "POST", { id: d.securityack });
      return navigate("Security & logs");
    }
    if (d.action === "securitybackup" || d.action === "securitynotify") {
      await api(
        "/api/msp/security/" +
          (d.action === "securitybackup" ? "backup" : "test-notification"),
        "POST",
        {},
      );
      await navigate(page);
      return toast(
        d.action === "securitybackup"
          ? "Backup completed"
          : "Notification request processed; check delivery status",
      );
    }
    if (d.securityresolve)
      return modal(
        "Resolve a verified alert",
        `<p>Acknowledgment alone does not fix a fault. Enter the reference for the completed fix and verification. Do not include patient information.</p>${field("Fix and test reference", "resolutionref")}`,
        async () => {
          await api("/api/msp/security/resolve-alert", "POST", {
            id: d.securityresolve,
            reference: $("#resolutionref").value.trim(),
          });
          $("#modal").close();
          await refresh();
          await navigate(page);
        },
      );
    if (d.action === "securityevidence")
      return modal(
        "Record completed verification",
        `<p>Record only checks you actually completed. Do not enter secrets, patient names, or filenames.</p><label class="field">Review<select id="evidencekind">${["restore_drill", "key_custody", "mfa_review", "pilot_review", "notification_receipt", "monitoring_review", "access_review", "endpoint_review", "credential_review", "activation_review"].map((k) => `<option value="${k}">${esc(k.replaceAll("_", " "))}</option>`).join("")}</select></label>${field("Evidence reference", "evidenceref", "", "text")}<p>Reviews expire after 30 days. Portal approval requires cloud technical checks and provider approvals. Practice endpoint review and pilot results are tracked separately.</p>`,
        async () => {
          await api("/api/msp/security/evidence", "POST", {
            kind: $("#evidencekind").value,
            reference: $("#evidenceref").value.trim(),
          });
          $("#modal").close();
          await refresh();
          await navigate(page);
        },
      );
    if (d.action === "securitymaintenance" || d.action === "securitystorage") {
      e.target.disabled = true;
      toast("Running security verification…");
      try {
        await api(
          "/api/msp/security/" +
            (d.action === "securitymaintenance"
              ? "maintenance"
              : "storage-check"),
          "POST",
          d.action === "securitystorage" ? { tenant } : {},
        );
        toast("Verification finished; review the recorded results");
      } finally {
        await navigate("Security & logs");
      }
      return;
    }
    if (d.action === "securityaccess") {
      const r = await api("/api/msp/security/access");
      modal(
        "Review privileged access",
        `<p>MSP administrators: ${r.administrators.map(esc).join(", ")}</p><div class="tablewrap"><table><thead><tr><th>Workspace ID</th><th>Member</th><th>Role</th></tr></thead><tbody>${r.members.map((m) => `<tr><td>${esc(m.tenant)}</td><td>${esc(m.email)}</td><td>${esc(m.role)}</td></tr>`).join("")}</tbody></table></div><p>Confirm only after you have reviewed these accounts. This records the review and does not change permissions.</p>`,
        async () => {
          await api("/api/msp/security/access-review", "POST", {});
          await navigate("Security & logs");
        },
        "Record completed review",
      );
      return;
    }
    if (d.action === "securityexport") {
      saveBlob(
        new Blob([JSON.stringify(data.security.events, null, 2)], {
          type: "application/json",
        }),
        "streamlined-vault-security-events.json",
      );
      return;
    }
    if (d.storagesetup)
      return workspaceDialog(user.tenants.find((t) => t.id === d.storagesetup));
    if (d.browsertransfers) {
      await api(
        `/api/tenants/${d.browsertransfers}/storage/browser-transfers`,
        "POST",
        {},
      );
      await refresh();
      await navigate(page);
      return toast("Browser transfers configured");
    }
    if (d.inviteuser)
      return modal("Send user email", `<p>Send enrollment or sign-in instructions to <strong>${esc(d.inviteuser)}</strong>?</p><p>The assigned practice role will stay unchanged. Enrollment invitations expire after seven days.</p>`, async () => {
        await api(base() + "/members/invitation", "POST", {email:d.inviteuser});
        $("#modal").close();
        await navigate("Team & access");
        toast("Email accepted by provider; inbox delivery is not yet confirmed");
      }, "Send email");
    if (d.manageusers) {
      tenant = d.manageusers;
      return navigate("Team & access");
    }
    if (d.action === "invite")
      return modal(
        "Add user to " + (user.tenants.find((t) => t.id === tenant)?.name || "practice"),
        `<p>Assign access to a verified identity. Identity enrollment and MFA must be arranged separately.</p>${field("Email address", "memberemail", "", "email")}<label class="field">Role<select id="memberrole"><option value="viewer">Viewer — browse and download</option><option value="uploader">Uploader — upload only</option><option value="editor">Editor — manage files</option><option value="admin">Administrator — manage practice</option></select></label>`,
        async () => {
          await api(base() + "/members", "POST", {
            email: $("#memberemail").value.trim(),
            role: $("#memberrole").value,
          });
          $("#modal").close();
          await navigate(page);
          toast("Access assigned");
        },
        "Assign access",
      );
    if (d.action === "downloaduploader") {
      b.disabled = true;
      try { await downloadUploader(); } finally { b.disabled = false; }
      return;
    }
    if (d.action === "newdevice") return await uploaderSetup();
    if (d.enrollment) {
      const r = await api(
        base() + `/devices/${d.enrollment}/enrollment`,
        "POST",
        {},
      );
      return enrollmentDialog(r);
    }
    if (d.editdevice) {
      const device = data.devices.find((x) => x.id === d.editdevice);
      return modal(
        "Edit uploader schedule",
        deviceFields(device),
        async () => {
          await api(base() + `/devices/${device.id}`, "PATCH", {
            policy: devicePolicy(),
          });
          $("#modal").close();
          await navigate("Uploaders");
          toast("Schedule saved. Applies on next device contact.");
        },
        "Save schedule",
      );
    }
    if (d.pausedevice) {
      const device = data.devices.find((x) => x.id === d.pausedevice);
      await api(base() + `/devices/${device.id}`, "PATCH", {
        paused: !device.paused,
      });
      await navigate("Uploaders");
      return toast(
        device.paused
          ? "Uploader resumed"
          : "Uploader paused; an in-flight part may finish",
      );
    }
    if (d.rundevice) {
      await api(base() + `/devices/${d.rundevice}/run`, "POST", {});
      return toast(
        config.demo
          ? "Preview only — no real device was contacted"
          : "Run queued for the next device contact",
      );
    }
    if (d.revokedevice)
      return modal(
        "Revoke this uploader?",
        `<p>This permanently disables this device credential. Stored files remain available. To reconnect, create a new enrollment.</p>`,
        async () => {
          await api(base() + `/devices/${d.revokedevice}`, "DELETE", {});
          $("#modal").close();
          await navigate("Uploaders");
        },
        "Revoke device",
      );
    if (d.deviceruns) {
      const runs = await api(base() + `/devices/${d.deviceruns}/runs`);
      return modal(
        "Uploader run history",
        runs.length
          ? runs
              .map(
                (r) =>
                  `<div class="row"><div><h3>${esc(r.status)}</h3><p>${date(r.created)} · ${r.uploaded} uploaded · ${r.skipped} unchanged/skipped · ${r.failed} failed</p></div></div>`,
              )
              .join("")
          : "<p>No completed run reports yet. Offline devices report when they reconnect.</p>",
        null,
      );
    }
    if (d.action === "uploaderhelp")
      return modal(
        "Set up a scheduled uploader",
        `<p>Download the current Windows installer from Add uploader and run it on the practice computer. Source folders are selected locally, and schedules are configured in this portal.</p><p>The agent runs at startup using Windows Task Scheduler. It resumes transfers and reports bounded run summaries. It never deletes source or cloud files.</p><p>The computer must remain awake and online. ${config.demo || preview ? "This preview simulates setup and does not install software." : "Download the installer directly on the practice computer; no USB transfer is needed."} This remains an unsigned pilot release, and the practice pilot must pass before scheduled protection is treated as verified.</p>`,
        null,
      );
    if (d.action === "export") {
      const events = await api(base() + "/audit");
      saveBlob(
        new Blob([JSON.stringify(events, null, 2)], {
          type: "application/json",
        }),
        "streamlined-vault-activity.json",
      );
      return toast("Activity exported");
    }
    if (d.action === "notices") {
      const notices = await api(base() + "/notices");
      return modal(
        "Your notifications",
        notices.length
          ? notices
              .map(
                (n) =>
                  `<div class="row"><p>${esc(n.title)}<br>${date(n.created)}</p></div>`,
              )
              .join("")
          : "<p>You’re all caught up. Capacity and automation alerts will appear here.</p>",
        null,
      );
    }
    if (d.action === "help")
      return modal(
        "A little help, right here.",
        `<p>Files: upload, download, rename, or move files to recoverable trash.</p><p>Uploaders: enroll a practice computer and schedule automatic file uploads.</p><p>Team & access: assign permissions to members of your practice.</p><p>For account enrollment, support, and production activation, contact your managed service administrator.</p>`,
        null,
      );
  } catch (e) {
    toast(e.message);
    b.disabled = false;
  }
});
async function boot() {
  try {
    const r = await fetch("/api/config");
    if (r.ok && r.headers.get("content-type")?.includes("application/json"))
      config = await r.json();
    else if ([200, 404, 405].includes(r.status)) {
      preview = true;
      config = {
        demo: true,
        ready: false,
        transferLimits: {
          maxFileBytes: 50 * 1024 ** 3,
          pilot: false,
          direct: false,
        },
      };
      demoAPI = await import("./demo.js?v=7");
    } else throw Error("Portal configuration unavailable");
    if (!config.demo && config.auth === "clerk") {
      clerkUI = await import("./clerk-client.js");
      await clerkUI.initialize(config.clerk);
    }
    try {
      if (clerkUI && clerkUI.signedIn())
        await api("/auth/complete", "POST", {});
      await refresh();
      await navigate("Overview");
    } catch (e) {
      authError = e.message;
      loginScreen();
    }
  } catch (e) {
    $("#root").innerHTML =
      `<div class="boot">Streamlined Vault<span>${esc(e.message)}. Reload or contact your administrator.</span></div>`;
  }
}
boot();
