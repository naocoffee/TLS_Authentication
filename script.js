"use strict";

/* =====================================================================
   データ定義
===================================================================== */

// 信頼できる認証局（CA）候補。毎ラウンド、このうち1つが証明書の
// 「発行者」として使われ、残りは選択肢の中のダミーとして混じる。
const TRUSTED_CAS = [
  { name: "GlobalTrust CA",     fp: "3F:A2:9B:71:C4:0E:88:5D" },
  { name: "NihonSSL 認証機構",   fp: "8C:11:4A:F0:2B:99:E7:36" },
  { name: "SecureRoot CA",      fp: "D5:67:1E:CA:83:4F:09:B2" },
  { name: "CyberShield CA",     fp: "62:F9:3D:A0:17:C8:55:E4" },
];

// 調査対象となるサイトのシナリオ。ドメインは架空のもの。
const SITE_SCENARIOS = [
  { siteName: "さくら銀行",     domain: "sakura-bank.example.com" },
  { siteName: "つばき信託銀行", domain: "tsubaki-trust.example.com" },
  { siteName: "ひかり通販",     domain: "hikari-shop.example.com" },
  { siteName: "あおぞら共済",   domain: "aozora-mutual.example.com" },
  { siteName: "こもれび保険",   domain: "komorebi-ins.example.com" },
];

// なりすましドメインを作る簡易パターン（タイポスクワッティング等）
function spoofDomain(domain) {
  const patterns = [
    (d) => d.replace(".com", "-secure.com"),
    (d) => d.replace(/^([a-z]+)-/, "$1$1-"),
    (d) => d.replace(".example.com", ".example.co"),
    (d) => "login." + d.replace(".example.com", "-verify.net"),
    (d) => d.replace("-", ""),
  ];
  const fn = patterns[Math.floor(Math.random() * patterns.length)];
  return fn(domain);
}

/* =====================================================================
   擬似ハッシュ関数（学習用のシミュレーションであり暗号学的ではない）
===================================================================== */
function pseudoHash(input) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = (h1 ^ (h1 >>> 16)) >>> 0;
  h2 = (h2 ^ (h2 >>> 16)) >>> 0;
  const hex = (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0"));
  return hex.toUpperCase();
}

function randomSignatureBlock() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < 64; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out.match(/.{1,16}/g).join(" ");
}

function randomValidity() {
  const startYear = 2024 + Math.floor(Math.random() * 2);
  return `${startYear}-04-01  〜  ${startYear + 1}-03-31`;
}

/* =====================================================================
   ラウンド生成
===================================================================== */
let state = null;
let scoreSolved = 0;
let scoreTotal = 0;
let scoreStreak = 0;

function buildRound() {
  const scenario = SITE_SCENARIOS[Math.floor(Math.random() * SITE_SCENARIOS.length)];
  const issuerCA = TRUSTED_CAS[Math.floor(Math.random() * TRUSTED_CAS.length)];
  const requestedDomain = scenario.domain;

  const isFake = Math.random() < 0.55;
  let failType = null;
  if (isFake) {
    failType = Math.random() < 0.5 ? "domain-mismatch" : "signature-invalid";
  }

  let subjectDomain = requestedDomain;
  if (failType === "domain-mismatch") {
    subjectDomain = spoofDomain(requestedDomain);
  }

  // 証明書の「内容」から計算されるハッシュ値（サブジェクト＋発行者に基づく）
  const computedHash = pseudoHash(subjectDomain + "|" + issuerCA.name + "|content");

  // 署名を復号すると得られるはずのハッシュ値
  let embeddedHash = computedHash;
  if (failType === "signature-invalid") {
    embeddedHash = pseudoHash(computedHash + "|forged-by-attacker");
  }

  return {
    scenario,
    requestedDomain,
    issuerCA,
    isFake,
    failType,
    subjectDomain,
    computedHash,
    embeddedHash,
    serverKeyFingerprint: pseudoHash(subjectDomain + "|serverkey").match(/.{1,4}/g).join(":"),
    signatureBlock: randomSignatureBlock(),
    validity: randomValidity(),
    selectedCA: null,
    decrypted: false,
    decryptedHash: null,
    judged: false,
  };
}

/* =====================================================================
   DOM参照
===================================================================== */
const el = (id) => document.getElementById(id);

const introScreen   = el("intro-screen");
const gameScreen    = el("game-screen");
const startBtn      = el("start-btn");
const resetBtn      = el("reset-btn");

const targetDomainEl = el("target-domain");
const certSubject    = el("cert-subject");
const certIssuer     = el("cert-issuer");
const certPubkey     = el("cert-pubkey");
const certValidity   = el("cert-validity");
const certSignature  = el("cert-signature");
const certSeal       = el("cert-seal");

const caListEl     = el("ca-list");
const decryptBtn   = el("decrypt-btn");
const verifyLog    = el("verify-log");
const hashCompare  = el("hash-compare");
const hashDecrypted= el("hash-decrypted");
const hashComputed = el("hash-computed");

const judgeSafeBtn  = el("judge-safe-btn");
const judgeBlockBtn = el("judge-block-btn");

const resultOverlay = el("result-overlay");
const resultCard    = el("result-card");
const resultIcon    = el("result-icon");
const resultTitle   = el("result-title");
const resultBody    = el("result-body");
const resultFacts   = el("result-facts");
const gotoStep4Btn  = el("goto-step4-btn");
const nextBtn       = el("next-btn");

const step4Panel   = el("step4-panel");
const s4PmsEl      = el("s4-pms");
const s4EncEl      = el("s4-enc");
const s4DecEl      = el("s4-dec");
const s4CommonEl   = el("s4-common");
const s4GenBtn     = el("s4-gen-btn");
const s4EncBtn     = el("s4-enc-btn");
const s4DecBtn     = el("s4-dec-btn");
const s4CommonBtn  = el("s4-common-btn");
const step4Result  = el("step4-result");
const step4NextBtn = el("step4-next-btn");

const scoreSolvedEl = el("score-solved");
const scoreTotalEl  = el("score-total");
const scoreStreakEl = el("score-streak");

/* =====================================================================
   描画
===================================================================== */
function renderRound() {
  targetDomainEl.textContent = state.requestedDomain;

  certSubject.textContent  = state.subjectDomain;
  certIssuer.textContent   = state.issuerCA.name;
  certPubkey.textContent   = state.serverKeyFingerprint;
  certValidity.textContent = state.validity;
  certSignature.textContent = state.signatureBlock;
  certSeal.textContent = "証";

  // CA一覧（毎ラウンド、issuerCAを含めシャッフルして表示）
  const shuffled = [...TRUSTED_CAS].sort(() => Math.random() - 0.5);
  caListEl.innerHTML = "";
  shuffled.forEach((ca) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ca-card";
    btn.dataset.name = ca.name;
    btn.innerHTML = `
      <span class="ca-card__name">${ca.name}</span>
      <span class="ca-card__fp mono">${ca.fp}</span>
    `;
    btn.addEventListener("click", () => selectCA(ca, btn));
    caListEl.appendChild(btn);
  });

  decryptBtn.disabled = true;
  verifyLog.innerHTML = "";
  hashCompare.classList.add("hidden");
  hashDecrypted.textContent = "-";
  hashComputed.textContent = "-";
  hashDecrypted.className = "hash-compare__value mono";
  hashComputed.className = "hash-compare__value mono";

  judgeSafeBtn.disabled = true;
  judgeBlockBtn.disabled = true;

  resetStep4();
  step4Panel.classList.add("hidden");

  gameScreen.classList.remove("hidden");
  introScreen.classList.add("hidden");
}

function selectCA(ca, btnEl) {
  if (state.decrypted) return; // 復号後は選び直せない
  state.selectedCA = ca;
  [...caListEl.children].forEach((c) => c.classList.remove("selected"));
  btnEl.classList.add("selected");
  decryptBtn.disabled = false;
}

function logLine(text) {
  const line = document.createElement("div");
  line.className = "verify-log__line";
  line.textContent = text;
  verifyLog.appendChild(line);
}

function runDecryption() {
  if (!state.selectedCA || state.decrypted) return;
  state.decrypted = true;
  decryptBtn.disabled = true;
  caListEl.querySelectorAll(".ca-card").forEach((c) => (c.style.pointerEvents = "none"));

  verifyLog.innerHTML = "";
  const lines = [
    `> 選択した鍵: ${state.selectedCA.name} (${state.selectedCA.fp})`,
    `> 証明書内の署名を復号しています...`,
  ];

  let decryptedHash;
  if (state.selectedCA.name !== state.issuerCA.name) {
    decryptedHash = pseudoHash(state.embeddedHash + "|wrong-key");
    lines.push(`> 鍵の対応が取れず、復号結果が不正な値になりました。`);
  } else {
    decryptedHash = state.embeddedHash;
    lines.push(`> 復号完了。ハッシュ値を取り出しました。`);
  }
  lines.push(`> 証明書の内容からハッシュ値を計算しています...`);
  lines.push(`> 2つのハッシュ値を比較します。`);

  state.decryptedHash = decryptedHash;

  lines.forEach((text, i) => {
    setTimeout(() => logLine(text), i * 320);
  });

  setTimeout(() => {
    hashCompare.classList.remove("hidden");
    hashDecrypted.textContent = decryptedHash;
    hashComputed.textContent = state.computedHash;
    const hashMatch = decryptedHash === state.computedHash;
    hashDecrypted.classList.add(hashMatch ? "match" : "mismatch");
    hashComputed.classList.add(hashMatch ? "match" : "mismatch");

    judgeSafeBtn.disabled = false;
    judgeBlockBtn.disabled = false;
  }, lines.length * 320 + 150);
}

/* =====================================================================
   判定
===================================================================== */
function evaluate(playerChoseSafe) {
  if (state.judged) return;
  state.judged = true;

  const correctCA   = state.selectedCA && state.selectedCA.name === state.issuerCA.name;
  const hashMatch   = state.decryptedHash === state.computedHash;
  const domainMatch = state.subjectDomain === state.requestedDomain;

  const isActuallySafe = correctCA && hashMatch && domainMatch;
  const playerCorrect = (isActuallySafe && playerChoseSafe) || (!isActuallySafe && !playerChoseSafe);

  scoreTotal++;
  if (playerCorrect) {
    scoreSolved++;
    scoreStreak++;
  } else {
    scoreStreak = 0;
  }
  scoreSolvedEl.textContent = scoreSolved;
  scoreTotalEl.textContent = scoreTotal;
  scoreStreakEl.textContent = scoreStreak;

  showResult(isActuallySafe, playerCorrect, { correctCA, hashMatch, domainMatch });
}

function showResult(isActuallySafe, playerCorrect, facts) {
  resultCard.classList.remove("result-card--safe", "result-card--danger");
  resultCard.classList.add(isActuallySafe ? "result-card--safe" : "result-card--danger");

  resultIcon.textContent = isActuallySafe ? "🔒" : "🚨";
  resultTitle.textContent = isActuallySafe
    ? "本物の証明書です。安全に接続できます。"
    : "なりすましの疑いがあります。接続を遮断しました。";

  let bodyText = playerCorrect
    ? "あなたの判定は正しい。捜査は的確だった。"
    : "残念、判定を誤った。証拠をもう一度よく確認しよう。";
  bodyText += isActuallySafe
    ? " この後、実際のTLS通信では鍵交換（STEP4）へ進む。"
    : " 証明書が不正なため、実際の通信では鍵交換は行われず接続が中止される。";
  resultBody.textContent = bodyText;

  resultFacts.innerHTML = "";
  const factList = [
    { ok: facts.correctCA,   textOk: "選択したCAは証明書の発行者と一致した",   textNg: "選択したCAが証明書の発行者と一致しなかった" },
    { ok: facts.hashMatch,   textOk: "復号したハッシュ値と計算したハッシュ値が一致した", textNg: "復号したハッシュ値と計算したハッシュ値が一致しなかった（署名が不正）" },
    { ok: facts.domainMatch, textOk: "証明書のドメイン名は接続先と一致した",   textNg: "証明書のドメイン名が接続先と一致しなかった（なりすましの可能性）" },
  ];
  factList.forEach((f) => {
    const row = document.createElement("div");
    row.className = "result-fact " + (f.ok ? "result-fact--ok" : "result-fact--ng");
    row.innerHTML = `<span class="result-fact__mark">${f.ok ? "OK" : "NG"}</span><span>${f.ok ? f.textOk : f.textNg}</span>`;
    resultFacts.appendChild(row);
  });

  gotoStep4Btn.classList.toggle("hidden", !isActuallySafe);

  resultOverlay.classList.remove("hidden");
}

/* =====================================================================
   STEP4: 鍵交換シミュレーション
===================================================================== */
let step4State = null;

function randomHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes; i++) {
    out += Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
  }
  return out.toUpperCase();
}

function resetStep4() {
  step4State = { pms: null, encrypted: null, decrypted: null, commonKey: null };
  s4PmsEl.textContent = "-";
  s4EncEl.textContent = "-";
  s4DecEl.textContent = "-";
  s4CommonEl.textContent = "-";
  s4GenBtn.disabled = false;
  s4EncBtn.disabled = true;
  s4DecBtn.disabled = true;
  s4CommonBtn.disabled = true;
  step4Result.classList.add("hidden");
}

s4GenBtn.addEventListener("click", () => {
  step4State.pms = randomHex(16);
  s4PmsEl.textContent = step4State.pms;
  s4GenBtn.disabled = true;
  s4EncBtn.disabled = false;
});

s4EncBtn.addEventListener("click", () => {
  // サーバー証明書に含まれる公開鍵で「暗号化」したことを表す（学習用の簡易表現）
  step4State.encrypted = btoa(step4State.pms);
  s4EncEl.textContent = `${step4State.encrypted}  ← 公開鍵: ${state.serverKeyFingerprint}`;
  s4EncBtn.disabled = true;
  s4DecBtn.disabled = false;
});

s4DecBtn.addEventListener("click", () => {
  // サーバーだけが持つ秘密鍵で復号し、元のプレマスターシークレットが復元されることを表す
  step4State.decrypted = atob(step4State.encrypted);
  const ok = step4State.decrypted === step4State.pms;
  s4DecEl.textContent = ok
    ? `${step4State.decrypted}（復号成功：秘密鍵はこのサーバーだけが持っている）`
    : "復号に失敗しました";
  s4DecBtn.disabled = true;
  s4CommonBtn.disabled = !ok;
});

s4CommonBtn.addEventListener("click", () => {
  step4State.commonKey = pseudoHash(step4State.pms + "|" + state.subjectDomain + "|session");
  s4CommonEl.textContent = step4State.commonKey;
  s4CommonBtn.disabled = true;
  step4Result.classList.remove("hidden");
});

step4NextBtn.addEventListener("click", () => {
  step4Panel.classList.add("hidden");
  state = buildRound();
  renderRound();
});

/* =====================================================================
   イベント配線
===================================================================== */
startBtn.addEventListener("click", () => {
  state = buildRound();
  renderRound();
});

decryptBtn.addEventListener("click", runDecryption);

judgeSafeBtn.addEventListener("click", () => evaluate(true));
judgeBlockBtn.addEventListener("click", () => evaluate(false));

nextBtn.addEventListener("click", () => {
  resultOverlay.classList.add("hidden");
  step4Panel.classList.add("hidden");
  state = buildRound();
  renderRound();
});

gotoStep4Btn.addEventListener("click", () => {
  resultOverlay.classList.add("hidden");
  resetStep4();
  step4Panel.classList.remove("hidden");
  step4Panel.scrollIntoView({ behavior: "smooth", block: "start" });
});

resetBtn.addEventListener("click", () => {
  scoreSolved = 0;
  scoreTotal = 0;
  scoreStreak = 0;
  scoreSolvedEl.textContent = "0";
  scoreTotalEl.textContent = "0";
  scoreStreakEl.textContent = "0";
  gameScreen.classList.add("hidden");
  introScreen.classList.remove("hidden");
});
