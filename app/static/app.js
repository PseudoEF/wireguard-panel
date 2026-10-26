function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return (n / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i];
}

function fmtAgo(ts, now) {
  if (!ts) return "никогда";
  const s = now - ts;
  if (s < 60) return "только что";
  if (s < 3600) return Math.floor(s / 60) + " мин назад";
  if (s < 86400) return Math.floor(s / 3600) + " ч назад";
  return new Date(ts * 1000).toLocaleString("ru-RU");
}

function showQr(id, name) {
  const img = document.getElementById("qr-img");
  const tooLarge = document.getElementById("qr-too-large");
  img.hidden = false;
  tooLarge.hidden = true;
  img.onerror = () => { img.hidden = true; tooLarge.hidden = false; };
  img.src = "/clients/" + id + "/qr?t=" + Date.now();
  document.getElementById("qr-title").textContent = name;
  document.getElementById("qr-download").href = "/clients/" + id + "/config";
  document.getElementById("qr-dialog").showModal();
}

// После выдачи конфига обновляем страницу, чтобы пропала пометка «конфиг устарел»
document.getElementById("qr-dialog").addEventListener("close", () => {
  location.replace(location.pathname);
});

async function refresh() {
  const errEl = document.getElementById("poll-error");
  let data;
  try {
    const r = await fetch("/api/stats", { cache: "no-store" });
    if (r.status === 401) { location.href = "/login"; return; }
    data = await r.json();
  } catch (e) {
    errEl.textContent = "Нет связи с панелью";
    errEl.hidden = false;
    return;
  }
  errEl.hidden = !data.error;
  errEl.textContent = data.error ? "Интерфейс недоступен: " + data.error : "";

  let online = 0, rx = 0, tx = 0;
  for (const c of data.clients) {
    const tr = document.querySelector(`tr[data-id="${c.id}"]`);
    if (!tr) continue;
    if (c.online) online++;
    rx += c.rx; tx += c.tx;
    tr.classList.toggle("online", c.online);
    tr.querySelector(".dot").title = !c.enabled ? "отключён" : c.online ? "онлайн" : "офлайн";
    tr.querySelector(".f-endpoint").textContent = c.endpoint ? c.endpoint.replace(/:\d+$/, "") : "—";
    tr.querySelector(".f-seen").textContent = fmtAgo(c.last_seen, data.now);
    tr.querySelector(".f-rx").textContent = fmtBytes(c.tx); // tx сервера = то, что получил клиент
    tr.querySelector(".f-tx").textContent = fmtBytes(c.rx);
  }
  document.getElementById("summary").textContent =
    `Клиентов: ${data.clients.length} · онлайн: ${online} · трафик с запуска туннеля: ↓ ${fmtBytes(tx)} ↑ ${fmtBytes(rx)}`;
}

if (document.getElementById("summary")) {
  refresh();
  setInterval(refresh, 5000);
}

const newId = new URLSearchParams(location.search).get("new");
if (newId) {
  history.replaceState(null, "", "/");
  const tr = document.querySelector(`tr[data-id="${newId}"]`);
  if (tr) showQr(newId, tr.querySelector("summary").textContent);
}
