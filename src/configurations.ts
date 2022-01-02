import AES from "crypto-js/aes";
import { EncryptionConfigurations } from "./types";

let configurations: EncryptionConfigurations = {
  key: null,
  driver: AES,
};

export function setEncryptionConfigurations(
  newConfigurations: EncryptionConfigurations
) {
  configurations = { ...configurations, ...newConfigurations };
}

export function getEncryptionConfig(key: keyof EncryptionConfigurations): any {
  return configurations[key];
}
