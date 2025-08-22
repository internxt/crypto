const envService = {
  getVariable,
};
const variableList = {
  serviceID: 'VITE_SERVICE_ID',
  templateID: 'VITE_TEMPLATE_ID',
  publicKey: 'VITE_PUBLIC_KEY',
  baseUrl: 'VITE_BASE_URL',
};

/**
 * Generates a mnemonic of required bit strength
 *
 * @param bits - The bit strength.
 * @returns The generated mnemonic.
 */
function getVariable(variable: keyof typeof variableList): string {
  const envKey = variableList[variable];
  if (!envKey) {
    throw new Error(`Unknown variable name: "${variable}"`);
  }
  const value = import.meta.env[envKey];
  if (!value) {
    throw new Error(`Variable "${variable}" is empty`);
  }
  return value;
}

export default envService;
