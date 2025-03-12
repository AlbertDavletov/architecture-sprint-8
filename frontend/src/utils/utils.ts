import Keycloak from 'keycloak-js'

export function checkAccess(keycloak: Keycloak): boolean {
    if (!keycloak?.token) {
        return false;
    }
    return true;
}

export function downloadFile(data: any, fileName: string = "file") {
    const jsonString = `data:text/json;chatset=utf-8,${encodeURIComponent(
        JSON.stringify(data, null, 2)
    )}`;
    const link = document.createElement("a");
    link.href = jsonString;
    link.download = `${fileName}.json`;
    link.click();
}
