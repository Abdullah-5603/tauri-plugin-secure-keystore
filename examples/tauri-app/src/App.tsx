import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type AuthMethod = "os" | "password";

async function setItem(
  key: string,
  value: string,
  requireAuth: AuthMethod | null = null,
): Promise<void> {
  await invoke("plugin:secure-keystore|set_item", { key, value, requireAuth });
}

async function getItem(
  key: string,
  requireAuth: AuthMethod | null = null,
): Promise<string | null> {
  const result = await invoke<{ value: string | null }>(
    "plugin:secure-keystore|get_item",
    { key, requireAuth },
  );
  return result.value ?? null;
}

async function deleteItem(
  key: string,
  requireAuth: AuthMethod | null = null,
): Promise<void> {
  await invoke("plugin:secure-keystore|delete_item", { key, requireAuth });
}

async function setLockPassword(password: string): Promise<void> {
  await invoke("plugin:secure-keystore|set_lock_password", { password });
}

async function unlockWithPassword(password: string): Promise<void> {
  await invoke("plugin:secure-keystore|unlock_with_password", { password });
}

async function lockKeystore(): Promise<void> {
  await invoke("plugin:secure-keystore|lock_keystore");
}

async function lockStatus(): Promise<{ hasLockPassword: boolean; unlocked: boolean }> {
  return await invoke("plugin:secure-keystore|lock_status");
}

const KEY = "example_key";
const AUTH_KEY = "example_key_auth"; // requireAuth: "os"
const PASSWORD_KEY = "example_key_password"; // requireAuth: "password"

function App() {
  const [value, setValue] = useState("");
  const [readBack, setReadBack] = useState<string | null | undefined>(
    undefined,
  );
  const [lockPassword, setLockPasswordInput] = useState("");
  const [log, setLog] = useState<string[]>([]);

  function append(line: string) {
    setLog((prev) => [...prev, line]);
  }

  function appendError(action: string, err: unknown) {
    append(`${action} -> error: ${err}`);
  }

  return (
    <main className="container">
      <h1>tauri-plugin-secure-keystore example</h1>

      <section>
        <h2>Plain storage (no lock — the default)</h2>
        <input
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
          placeholder="Value to store"
        />
        <div className="row">
          <button
            onClick={async () => {
              await setItem(KEY, value);
              append(`setItem("${KEY}", "${value}")`);
            }}
          >
            Set
          </button>
          <button
            onClick={async () => {
              const result = await getItem(KEY);
              setReadBack(result);
              append(`getItem("${KEY}") -> ${JSON.stringify(result)}`);
            }}
          >
            Get
          </button>
          <button
            onClick={async () => {
              await deleteItem(KEY);
              setReadBack(undefined);
              append(`deleteItem("${KEY}")`);
            }}
          >
            Delete
          </button>
        </div>
        {readBack !== undefined && (
          <p>Read back: {JSON.stringify(readBack)}</p>
        )}
      </section>

      <section>
        <h2>requireAuth: "os" (mobile only — biometric / PIN / pattern / password)</h2>
        <div className="row">
          <button
            onClick={async () => {
              try {
                await setItem(AUTH_KEY, value, "os");
                append(`setItem("${AUTH_KEY}", "${value}", "os") -> prompted, stored`);
              } catch (err) {
                appendError('setItem(.., "os")', err);
              }
            }}
          >
            Set (os)
          </button>
          <button
            onClick={async () => {
              try {
                const result = await getItem(AUTH_KEY, "os");
                append(`getItem("${AUTH_KEY}", "os") -> ${JSON.stringify(result)}`);
              } catch (err) {
                appendError('getItem(.., "os")', err);
              }
            }}
          >
            Get (os)
          </button>
        </div>
        <p className="hint">
          On desktop this always rejects with UnsupportedPlatform — that's
          expected, see the README.
        </p>
      </section>

      <section>
        <h2>requireAuth: "password" (app-managed, works everywhere)</h2>
        <input
          value={lockPassword}
          onChange={(e) => setLockPasswordInput(e.currentTarget.value)}
          placeholder="Lock password / PIN / pattern string"
        />
        <div className="row">
          <button
            onClick={async () => {
              try {
                await setLockPassword(lockPassword);
                append("setLockPassword(...) -> ok, session unlocked");
              } catch (err) {
                appendError("setLockPassword", err);
              }
            }}
          >
            Set lock password
          </button>
          <button
            onClick={async () => {
              try {
                await unlockWithPassword(lockPassword);
                append("unlockWithPassword(...) -> ok");
              } catch (err) {
                appendError("unlockWithPassword", err);
              }
            }}
          >
            Unlock
          </button>
          <button
            onClick={async () => {
              await lockKeystore();
              append("lock() -> session cleared");
            }}
          >
            Lock
          </button>
          <button
            onClick={async () => {
              const status = await lockStatus();
              append(`lockStatus() -> ${JSON.stringify(status)}`);
            }}
          >
            Status
          </button>
        </div>
        <div className="row">
          <button
            onClick={async () => {
              try {
                await setItem(PASSWORD_KEY, value, "password");
                append(`setItem("${PASSWORD_KEY}", "${value}", "password") -> ok`);
              } catch (err) {
                appendError('setItem(.., "password")', err);
              }
            }}
          >
            Set (password)
          </button>
          <button
            onClick={async () => {
              try {
                const result = await getItem(PASSWORD_KEY, "password");
                append(`getItem("${PASSWORD_KEY}", "password") -> ${JSON.stringify(result)}`);
              } catch (err) {
                appendError('getItem(.., "password")', err);
              }
            }}
          >
            Get (password)
          </button>
        </div>
      </section>

      <ul>
        {log.map((line, i) => (
          <li key={i}>{line}</li>
        ))}
      </ul>
    </main>
  );
}

export default App;
