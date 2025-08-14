const envService = {
  getVariable,
};
const variableList = {
  serviceID: 'REACT_APP_SERVICE_ID',
  templateID: 'REACT_APP_TEMPLATE_ID',
  publicKey: 'REACT_APP_PUBLIC_KEY',
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
