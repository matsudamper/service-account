"use strict";

// アカウントトークンはメモリにだけ持つ。再読み込みしたらログインし直す
let accountToken = null;
let conditionalAbort = null;

const app = document.getElementById("app");
const message = document.getElementById("message");

function showMessage(text) {
  message.textContent = text;
}

async function api(path, { method = "POST", body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = "Bearer " + token;
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  return { ok: response.ok, status: response.status, json };
}

const loginErrors = {
  not_accepted: "ユーザー名かパスワードが違います",
  too_many_attempts: "失敗が多すぎます。しばらく待ってからやり直してください",
};

function supportsPasskey() {
  return typeof PublicKeyCredential !== "undefined" &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function";
}

async function passkeyAssertion(mediation) {
  const options = await api("/api/login/passkey/options");
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.json);
  const request = { publicKey };
  if (mediation) {
    conditionalAbort = new AbortController();
    request.mediation = mediation;
    request.signal = conditionalAbort.signal;
  }
  const credential = await navigator.credentials.get(request);
  return credential;
}

async function loginWithPasskeyCredential(credential, onLoggedIn) {
  const result = await api("/api/login/passkey", { body: { credential: credential.toJSON() } });
  if (!result.ok) {
    showMessage("パスキーでログインできませんでした");
    return;
  }
  accountToken = result.json.accountToken;
  await onLoggedIn();
}

// 入力欄の候補にパスキーを出す。選ばれたらそのままログインする
async function startConditionalPasskey(onLoggedIn) {
  if (!supportsPasskey()) return;
  if (typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
  try {
    const credential = await passkeyAssertion("conditional");
    if (credential) await loginWithPasskeyCredential(credential, onLoggedIn);
  } catch (e) {
    // ボタンからのログインに切り替えたときに中断される
  }
}

function setupLogin(onLoggedIn) {
  const form = document.getElementById("login-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showMessage("");
    const result = await api("/api/login/password", {
      body: {
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      },
    });
    if (!result.ok) {
      showMessage(loginErrors[result.json?.error] ?? "ログインできませんでした");
      return;
    }
    accountToken = result.json.accountToken;
    await onLoggedIn();
  });

  const passkeyButton = document.getElementById("passkey-login-button");
  if (!supportsPasskey()) {
    passkeyButton.hidden = true;
    return;
  }
  passkeyButton.addEventListener("click", async () => {
    showMessage("");
    conditionalAbort?.abort();
    try {
      const credential = await passkeyAssertion(null);
      await loginWithPasskeyCredential(credential, onLoggedIn);
    } catch (e) {
      showMessage("パスキーでログインできませんでした");
    }
  });
  startConditionalPasskey(onLoggedIn);
}

// ---- 認可（各サービスへのログイン）----

function setupAuthorize() {
  const authorizeRequest = JSON.parse(app.dataset.authorizeRequest);
  setupLogin(async () => {
    const result = await api("/api/authorize", { body: authorizeRequest, token: accountToken });
    if (!result.ok) {
      showMessage(result.json?.message ?? "ログインできませんでした");
      return;
    }
    location.assign(result.json.redirectUrl);
  });
}

// ---- アカウント設定 ----

const passwordErrors = {
  invalid_password: "パスワードは 20〜256 文字で、英数字と記号 !@#$%^&*()_+-?<>,. だけを使ってください",
};

const passkeyErrors = {
  not_accepted: "パスキーを登録できませんでした",
  invalid_name: "名前は 1〜64 文字にしてください",
  already_registered: "このパスキーは登録済みです",
  last_login_method: "パスワードが無いので、最後のパスキーは削除できません",
  no_passkey: "パスキーが無いので、パスワードは削除できません",
  not_found: "パスキーが見つかりません",
};

async function accountApi(path, options) {
  const result = await api(path, { ...options, token: accountToken });
  if (result.status === 401) {
    accountToken = null;
    document.getElementById("settings-section").hidden = true;
    document.getElementById("login-section").hidden = false;
    showMessage("時間が経ったので、もう一度ログインしてください");
  }
  return result;
}

async function loadAccount() {
  const result = await accountApi("/api/account", { method: "GET" });
  if (!result.ok) return;
  const account = result.json;
  document.getElementById("login-section").hidden = true;
  document.getElementById("settings-section").hidden = false;
  document.getElementById("account-username").textContent = account.username;
  document.getElementById("password-form-username").value = account.username;
  document.getElementById("password-state").textContent = account.hasPassword ? "設定済み" : "未設定";
  document.getElementById("delete-password-button").hidden = !account.hasPassword;

  const list = document.getElementById("passkey-list");
  list.replaceChildren();
  for (const passkey of account.passkeys) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = passkey.name + "（" + new Date(passkey.createdAtEpochMillis).toLocaleDateString() + " 登録）";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "danger";
    button.textContent = "削除";
    button.addEventListener("click", async () => {
      if (!confirm(passkey.name + " を削除しますか？")) return;
      const deleted = await accountApi("/api/account/passkeys/" + encodeURIComponent(passkey.id), { method: "DELETE" });
      showMessage(deleted.ok ? "削除しました" : (passkeyErrors[deleted.json?.error] ?? "削除できませんでした"));
      await loadAccount();
    });
    item.append(name, button);
    list.append(item);
  }
}

function setupAccount() {
  setupLogin(async () => {
    showMessage("");
    await loadAccount();
  });

  document.getElementById("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("new-password");
    const result = await accountApi("/api/account/password", { method: "PUT", body: { newPassword: input.value } });
    if (result.ok) {
      input.value = "";
      showMessage("パスワードを変更しました");
      await loadAccount();
    } else if (result.status !== 401) {
      showMessage(passwordErrors[result.json?.error] ?? "パスワードを変更できませんでした");
    }
  });

  document.getElementById("delete-password-button").addEventListener("click", async () => {
    if (!confirm("パスワードを削除しますか？以後はパスキーでだけログインできます")) return;
    const result = await accountApi("/api/account/password", { method: "DELETE" });
    showMessage(result.ok ? "パスワードを削除しました" : (passkeyErrors[result.json?.error] ?? "削除できませんでした"));
    await loadAccount();
  });

  const passkeyForm = document.getElementById("passkey-form");
  if (typeof PublicKeyCredential === "undefined" || typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function") {
    passkeyForm.hidden = true;
    return;
  }
  passkeyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const options = await accountApi("/api/account/passkeys/options");
    if (!options.ok) return;
    let credential;
    try {
      credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.json) });
    } catch (e) {
      showMessage("パスキーを登録できませんでした");
      return;
    }
    const nameInput = document.getElementById("passkey-name");
    const result = await accountApi("/api/account/passkeys", { body: { name: nameInput.value, credential: credential.toJSON() } });
    if (result.ok) {
      nameInput.value = "";
      showMessage("パスキーを登録しました");
      await loadAccount();
    } else if (result.status !== 401) {
      showMessage(passkeyErrors[result.json?.error] ?? "パスキーを登録できませんでした");
    }
  });
}

if (app.dataset.page === "authorize") setupAuthorize();
if (app.dataset.page === "account") setupAccount();
