import { invoke } from "@tauri-apps/api/core";

/**
 * Store a value under `key`, encrypted with an Android Keystore-backed
 * AES-256-GCM key. Overwrites any existing value for the same key.
 */
export async function setItem(key: string, value: string): Promise<void> {
  await invoke("plugin:secure-keystore|set_item", { key, value });
}

/**
 * Retrieve and decrypt the value stored under `key`, or `null` if nothing
 * is stored for it.
 */
export async function getItem(key: string): Promise<string | null> {
  const result = await invoke<{ value: string | null }>(
    "plugin:secure-keystore|get_item",
    { key },
  );
  return result.value ?? null;
}

/** Remove the value stored under `key`, if any. */
export async function deleteItem(key: string): Promise<void> {
  await invoke("plugin:secure-keystore|delete_item", { key });
}
