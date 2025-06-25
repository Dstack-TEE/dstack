import crypto from "crypto";

type SortableValue = string | number | boolean | null | undefined | SortableObject | SortableArray;
interface SortableObject {
  [key: string]: SortableValue;
}
interface SortableArray extends Array<SortableValue> {}

function sortObject(obj: SortableValue): SortableValue {
  if (obj === undefined || obj === null) {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObject);
  } else if (obj && typeof obj === "object" && obj.constructor === Object) {
    return Object.keys(obj)
      .sort()
      .reduce((result: SortableObject, key) => {
        const value = (obj as SortableObject)[key];
        result[key] = sortObject(value);
        return result;
      }, {});
  }
  return obj;
}

export interface AppCompose extends SortableObject {
  runner?: string;
  docker_compose_file?: string;
  bash_script?: string;
  pre_launch_script?: string;
}

function preprocessAppCompose(dic: AppCompose): AppCompose {
  const obj: AppCompose = { ...dic };
  if (obj.runner === "bash" && "docker_compose_file" in obj) {
    delete obj.docker_compose_file;
  } else if (obj.runner === "docker-compose" && "bash_script" in obj) {
    delete obj.bash_script;
  }
  if ("pre_launch_script" in obj && !obj.pre_launch_script) {
    delete obj.pre_launch_script;
  }
  return obj;
}

function dumpAppCompose(dic: AppCompose): string {
  const ordered = sortObject(dic);
  let json = JSON.stringify(ordered, null, 4);
  json = json.replace(/": /g, '":');
  return json;
}

export function getComposeHash(app_compose: AppCompose): string {
  const preprocessed = preprocessAppCompose(app_compose);
  const manifest_str = dumpAppCompose(preprocessed);
  return crypto.createHash("sha256").update(manifest_str, "utf8").digest("hex");
}