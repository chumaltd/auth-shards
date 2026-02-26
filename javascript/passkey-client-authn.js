let authnOptions = null;
let abortController = new AbortController();
const is_l3_available = () => !!globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON;

export async function load_challenge(url_challenge) {
    if (!(navigator.credentials.get && await PublicKeyCredential.isConditionalMediationAvailable)) {
        return false;
    }

    const res_challenge = await fetch(url_challenge, { method: 'POST' });
    const response = await res_challenge.json();
    authnOptions = parse_request(response);
    return authnOptions;
}

export async function setup_conditional(url_auth) {
    if (!authnOptions) return;

    try {
        const credential = await navigator.credentials.get({
            publicKey: authnOptions.publicKey,
            mediation: 'conditional',
            signal: abortController.signal
        });
        return await submit_credential(url_auth, credential);
    } catch (err) {
        if (err.name !== 'AbortError') console.error(err);
    }
}

export async function passkey_btn_handler(url_auth) {
    if (!authnOptions) return;

    abortController?.abort();
    abortController = new AbortController();
    try {
        const options = {
            publicKey: authnOptions.publicKey,
            mediation: 'optional',
            signal: abortController.signal
        };
        const credential = await navigator.credentials.get(options);
        return await submit_credential(url_auth, credential);
    } catch (err) {
        if (err.name !== 'AbortError') console.error(err);
    }
}

function parse_request(response) {
    if (is_l3_available()) {
        return {
            publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(response.publicKey)
        };
    } else {
        response.publicKey.challenge = base64url2ab(response.publicKey.challenge);
        response.publicKey.allowCredentials?.forEach(ac => {
            ac.id = base64url2ab(ac.id);
        });
        return response;
    }
}

async function submit_credential(url, credential) {
    if (credential) {
        let credential_json;
        if (is_l3_available()) {
            credential_json = credential.toJSON();
        } else {
            credential_json = serialize_fallback(credential);
        }
        return await fetch(url, {
            body: JSON.stringify(credential_json),
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
    }
}

function serialize_fallback(pubkey_credential) {
    return {
        id: pubkey_credential.id,
        rawId: ab2base64url(pubkey_credential.rawId),
        type: pubkey_credential.type,
        response: {
            authenticatorData: ab2base64url(pubkey_credential.response.authenticatorData),
            clientDataJSON: ab2base64url(pubkey_credential.response.clientDataJSON),
            signature: ab2base64url(pubkey_credential.response.signature),
            userHandle: ab2base64url(pubkey_credential.response.userHandle),
        },
        extensions: pubkey_credential.extensions
    };
}

function ab2base64url(ab) {
    function base642base64url(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=*$/g, '')
    }

    const str = String.fromCharCode.apply(null, new Uint8Array(ab))
    return base642base64url(window.btoa(str));
}

function base64url2ab(base64url) {
    function base642ab(base64) {
        const str = window.atob(base64);
        const len = str.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        return bytes.buffer;
    }
    function base64url2base64(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = base64.length % 4;
        if (padding > 0) {
            return base64 + '===='.slice(padding);
        }
        return base64;
    }

    return base642ab(base64url2base64(base64url));
}
