export type EncryptionConfigurations = {
  /**
   * Set encryption default key
   */
  key?: string;
  /**
   * Set encryption default driver
   *
   * @prefers AES
   */
  driver?: any;
};
