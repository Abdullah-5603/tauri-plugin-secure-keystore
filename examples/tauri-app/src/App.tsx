import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

async function setItem(key: string, value: string): Promise<void> {
  await invoke("plugin:secure-keystore|set_item", { key, value });
}

async function getItem(key: string): Promise<string | null> {
  const result = await invoke<{ value: string | null }>(
    "plugin:secure-keystore|get_item",
    { key },
  );
  return result.value ?? null;
}

async function deleteItem(key: string): Promise<void> {
  await invoke("plugin:secure-keystore|delete_item", { key });
}

const KEY = "example_key";

function App() {
  const [value, setValue] = useState("");
  const [readBack, setReadBack] = useState<string | null | undefined>(
    undefined,
  );
  const [log, setLog] = useState<string[]>([]);

  function append(line: string) {
    setLog((prev) => [...prev, line]);
  }

  return (
    <main className="container">
      <h1>tauri-plugin-secure-keystore example</h1>

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

      {readBack !== undefined && <p>Read back: {JSON.stringify(readBack)}</p>}

      <ul>
        {log.map((line, i) => (
          <li key={i}>{line}</li>
        ))}
      </ul>
    </main>
  );
}

export default App;
