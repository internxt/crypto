const envService = {
  getVariable,
};
const variableList = {
  serviceID: 'VITE_SERVICE_ID',
  templateID: 'VITE_TEMPLATE_ID',
  publicKey: 'VITE_PUBLIC_KEY',
  baseUrl: 'VITE_BASE_URL',
};

function getVariable(variable: keyof typeof variableList): string {
  const envKey = variableList[variable];
  if (!envKey) {
    throw new Error(`Unknown variable name: "${variable}"`);
  }
  const value = import.meta.env[envKey];
  return value;
}

export default envService;
